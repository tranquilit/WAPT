program waptdeploy;

{$mode delphiunicode}

uses
  Classes,
  Windows,
  SysUtils,
  uwaptdeployres,
  superobject,
  tiswinhttp,
  DCPsha256,
  synautil,
  soutils,
  tisstrings,
  tiscommon,
  waptwinutils;


  // Trigger a local update of available packages. (require local service to be running)
  function UpdateStatus(notify_server:Boolean): ansistring;
  var
    port, Data, notify: string;
  begin
    port := WaptIniReadString('waptservice_port', '8088');
    if notify_server then
      notify:='1'
    else
      notify:='0';
    Data := httpGetString('http://127.0.0.1:' + port + '/update.json?notify_server='+notify+'&notify_user=0');
    Result := Data;
  end;

  function httpGetDate(url: RawByteString): TDateTime;
  var
    headers, line: ansistring;
  begin
    Result := 0;
    headers := httpGetHeaders(url);
    if headers <> '' then
    begin
{HTTP/1.1 200 OK
Date: Fri, 10 Apr 2015 10:18:54 GMT
Server: Apache
Last-Modified: Fri, 10 Apr 2015 10:15:02 GMT
ETag: "81fd1-82df-5135c099975fd"
Accept-Ranges: bytes
Content-Length: 33503
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive}
      Headers := ReplaceString(Headers, #13#10, #13);
      while Headers <> '' do
      begin
        line := StrToken(Headers, #13);
        if pos('Last-Modified:', line) = 1 then
        begin
          Result := DecodeRfcDateTime(Copy(line, pos(':', line) + 2, 255));
          exit;
        end;
      end;
    end;
  end;


  //Return true is one  of the connected network card has an IPV4 in the same subnetwork as IP
  function SameNet(connected: ISuperObject; IP: ansistring): boolean;
  var
    conn: ISuperObject;
  begin
    for conn in Connected do
    begin
      //Assumed first ip is ipv4 and second is IPV6... in the wmic network value object
      if SameIPV4Subnet(conn['ipaddress'].AsArray.S[0], IP,
        conn['ipsubnet'].AsArray.S[0]) then
      begin
        Result := True;
        Exit;
      end;
    end;
    Result := False;
  end;

  function GetMainWaptRepo: string;
  var
    rec, recs, ConnectedIps, ServerIp: ISuperObject;
    url, dnsdomain: ansistring;
    PackagesDate: TDateTime;
  begin
    Result := WaptIniReadString('repo_url', '');
    if Result <> '' then
      exit;

    dnsdomain := GetDNSDomain;
    if dnsdomain <> '' then
    begin
      ConnectedIps := NetworkConfig;
      //SRV _wapt._tcp
      recs := DNSSRVQuery('_wapt._tcp.' + dnsdomain);
      for rec in recs do
      begin
        if rec.I['port'] = 443 then
          url := 'https://' + rec.S['name'] + '/wapt'
        else
          url := 'http://' + rec.S['name'] + ':' + rec.S['port'] + '/wapt';
        rec.S['url'] := url;
        try
          ServerIp := DNSAQuery(rec.S['name']);
          if ServerIp.AsArray.Length > 0 then
            rec.B['outside'] := not SameNet(ConnectedIps, ServerIp.AsArray.S[0])
          else
            rec.B['outside'] := True;
        except
          rec.B['outside'] := True;
        end;
        // order is priority asc but wieght desc
        rec.I['weight'] := -rec.I['weight'];
      end;
      SortByFields(recs, ['outside', 'priority', 'weight']);

      for rec in recs do
        try
          writeln('trying ' + rec.S['url'] + '/Packages');
          Result := rec.S['url'];
          PackagesDate := httpGetDate(Result + '/Packages');
          if PackagesDate > 0 then
            Exit;
        except
          on E: Exception do
            writeln('Unable to HEAD ' + rec.S['url'] + '/Packages' + ' ' + E.Message);
        end;

      //CNAME wapt.
      recs := DNSCNAMEQuery('wapt' + dnsdomain);
      for rec in recs do
        try
          Result := 'http://' + rec.AsString + '/wapt';
          writeln('trying ' + Result + '/Packages');
          PackagesDate := httpGetDate(Result + '/Packages');
          if PackagesDate > 0 then
            Exit;
        except
          on E: Exception do
            writeln('Unable to HEAD ' + Result + '/Packages' + ' ' + E.Message);
        end;

      //A wapt
      Result := 'http://wapt.' + dnsdomain + '/wapt';
      writeln('trying ' + Result + '/Packages');
      try
        PackagesDate := httpGetDate(Result + '/Packages');
        if PackagesDate > 0 then
          Exit;
      except
        on E: Exception do
          writeln('Unable to HEAD ' + Result + '/Packages' + ' ' + E.Message);
      end;
    end;
    Result := '';
  end;

  function BinToStr(const Bin: array of byte): ansistring;
  const
    HexSymbols = '0123456789ABCDEF';
  var
    i: integer;
  begin
    SetLength(Result, 2 * Length(Bin));
    for i := 0 to Length(Bin) - 1 do
    begin
      Result[1 + 2 * i + 0] := HexSymbols[1 + Bin[i] shr 4];
      Result[1 + 2 * i + 1] := HexSymbols[1 + Bin[i] and $0F];
    end;
  end;

  function SHA256Hash(FilePath: ansistring): ansistring;
  var
    Context: TDCP_sha256;
    Buf: PByte;
    BufSize, ReadSize, TotalSize: integer;
    FileStream: TFileStream;
    RawDigest: array[0..31] of byte;
  begin
    Result := '';
    FileStream := nil;
    Buf := nil;
    Context := nil;

    TotalSize := 0;
    Bufsize := 32 * 1024; // 32k

    try
      FileStream := TFileStream.Create(FilePath, fmOpenRead);
      FileStream.Position := 0;
      Buf := GetMem(BufSize);
      Context := TDCP_sha256.Create(nil);
      Context.Init;

      while True do
      begin
        ReadSize := FileStream.Read(Buf^, BufSize);
        if ReadSize <= 0 then
          break;
        Context.Update(Buf^, ReadSize);
      end;

      Context.Final(RawDigest);

      Result := BinToStr(RawDigest);

    finally
      if FileStream <> nil then
        FileStream.Free;
      if Buf <> nil then
        FreeMem(Buf);
      if Context <> nil then
        Context.Free;
    end;
  end;


  // Returns only non options arguments of command line (those not starting with -- or -)
  function CommandParams: TDynStringArray;
  var
    i, p: integer;
  begin
    SetLength(Result, Paramcount);
    p := 0;
    for i := 1 to Paramcount do
    begin
      if (ParamStr(i) <> '') and (ParamStr(i)[1] <> '-') then
      begin
        Result[p] := ParamStr(i);
        Inc(p);
      end;
    end;
    SetLength(Result, p);
  end;

  //Return a map of the options of command line (starting with - or --)
  function CommandOptions: ISuperObject;
  var
    i: integer;
    line, key, Value: ansistring;
  begin
    Result := TSuperObject.Create(stObject);
    for i := 1 to Paramcount do
    begin
      line := ParamStr(i);
      if (line <> '') and (line[1] = '-') then
      begin
        if pos('--', line) = 1 then
        begin
          line := copy(line, 3, length(line));
          key := StrToken(line, '=');
          Value := line;
          Result.S[key] := Value;
        end
        else
        if pos('-', line) = 1 then
        begin
          line := copy(line, 2, length(line));
          key := line[1];
          Value := trim(copy(line, 2, length(line)));
          Result.S[key] := Value;
        end;
      end;
    end;
  end;

var
  tmpDir, waptsetupPath, localVersion, requiredVersion, getVersion: ansistring;
  res: ansistring;
  waptdeploy, waptsetupurl, hashString: ansistring;

{$R *.res}

const
  defaultwapt: ansistring = 'wapt';
  minversion: ansistring = '1.2.4.0';
  _mainrepo: ansistring = '';

var
  cmdparams: TDynStringArray;
  cmdoptions: ISuperObject;
  mergetasks: Ansistring;
  setuphash:AnsiString;
  setupcmdline:AnsiString;

function mainrepo:AnsiString;
begin
  if _mainrepo = '' then
  begin
    if cmdoptions.AsObject.Exists('repo_url') then
      _mainrepo := cmdoptions.S['repo_url']
    else
      try
        _mainrepo := GetMainWaptRepo;
      except
        on E: Exception do
        begin
          Writeln('Unable to discover the wapt repository: ' + E.Message);
          if GetDNSDomain <> '' then
            _mainrepo := 'http://wapt.' + GetDNSDomain + '/wapt'
          else
            _mainrepo := 'http://wapt/wapt';
        end;
      end;
  end;
  result := _mainrepo;
end;

begin
  cmdparams := CommandParams;
  cmdoptions := CommandOptions;

  if cmdoptions.AsObject.Exists('help') or cmdoptions.AsObject.Exists('h') then
  begin
    Writeln(rsUsage1);
    Writeln(Format(rsUsage2, [minversion]));
    Writeln(Format(rsUsage3, [defaultwapt]));
    Writeln(Format(rsUsage4, []));
    Writeln(Format(rsUsage5, []));
    Writeln(Format(rsUsage6, []));
    Exit;
  end;

  if cmdoptions.AsObject.Exists('force') then
  begin
    localVersion := '';
    requiredVersion := 'force';
  end
  else
  if cmdoptions.AsObject.Exists('minversion') then
  begin
    localVersion := LocalWaptVersion;
    requiredVersion := cmdoptions.S['minversion'];
  end
  else
  begin
    localVersion := LocalWaptVersion;
    if Length(cmdparams) >= 1 then
      requiredVersion := cmdparams[0];
  end;

  hashString := '';
  if cmdoptions.AsObject.Exists('hash') then
    hashString := cmdoptions.S['hash'];

  mergetasks := 'useWaptServer';
  if cmdoptions.AsObject.Exists('tasks') then
    mergetasks := cmdoptions.S['tasks'];

  waptsetupurl := '';
  writeln('WAPT version: ' + localVersion);
  if (requiredVersion = '') or (requiredVersion = 'force') then
  begin
    requiredVersion := minversion;
    try
      writeln('Trying to get '+mainrepo + '/waptdeploy.version ...');
      waptdeploy := httpGetString(mainrepo + '/waptdeploy.version');
      waptdeploy := StringReplace(waptdeploy, #13#10, #10, [rfReplaceAll]);
      requiredVersion := trim(StrToken(waptdeploy, #10));
      if requiredVersion = '' then
        requiredVersion := minversion;
      waptsetupurl := trim(StrToken(waptdeploy, #10));
      if waptsetupurl = '' then
        waptsetupurl := mainrepo + '/waptagent.exe';
      writeln('Got waptdeploy.version');
      writeln('   required version:' + requiredVersion);
      writeln('   download URL :' + waptsetupurl);
    except
      requiredVersion := minversion;
      waptsetupurl := mainrepo + '/waptagent.exe';
    end;
  end;

  writeln('WAPT required version: ' + requiredVersion);
  if (localVersion = '') or (CompareVersion(localVersion, requiredVersion) < 0) or
    (requiredVersion = 'force') then
    try
      if cmdoptions.AsObject.Exists('waptsetupurl') then
        waptsetupurl := cmdoptions.S['waptsetupurl'] ;

      if waptsetupurl='' then
        waptsetupurl := mainrepo + '/waptagent.exe';

      tmpDir := GetUniqueTempdir('wapt');
      mkdir(tmpDir);
      waptsetupPath := tmpDir + '\waptagent.exe';
      Writeln('Wapt agent path: ' + waptsetupPath);
      writeln('Wget new waptagent ' + waptsetupurl);
      wget(waptsetupurl, waptsetupPath,Nil,Nil,True,False);

      if (HashString <> '')then
      begin
        setuphash:=SHA256Hash(waptsetupPath);
        Writeln('SHA256 hash of downloaded setup file: '+setuphash);
        if setuphash<>hashString then
        begin
          WriteLn(rsHashError);
          ExitCode:=10;
          Exit;
        end;
      end;

      getVersion := GetApplicationVersion(waptsetupPath);
      writeln('Got version: ' + getVersion);
      if (requiredVersion = 'force') or
        (CompareVersion(getVersion, requiredVersion) >= 0) then
      begin
        setupcmdline:=waptsetupPath + ' /VERYSILENT /MERGETASKS=""' + mergetasks + '""';
        writeln(Format(rsInstall,[setupcmdline]));
        res := '';
        if GetDosOutput(setupcmdline, '', res) then
        begin
          writeln(Format(rsInstallOK, [LocalWaptVersion]))
        end
        else
        begin
          writeln(Format(rsInstallError,[res]));
          ExitCode:=11;
          Exit;
        end;
      end
      else
      begin
        writeln(rsVersionError);
        ExitCode:=12;
        Exit;
      end;
    finally
      writeln(rsCleanup);
      if DirectoryExists(tmpDir) then
      begin
        DeleteFile(waptsetupPath);
        RemoveDirectory(pansichar(tmpDir));
      end;
      UpdateStatus(True);
    end
  else
  begin
    writeln(rsNothingToDo);
    UpdateStatus(False);
  end;

end.
