program waptdeploy;

{$mode delphiunicode}

uses
  Classes,
  SysUtils,
  uwaptdeployres,
  superobject,
  tiswinhttp,
  synautil,
  soutils,
  tisstrings,
  tiscommon,
  waptwinutils;

  procedure WaitPendingTasks(timeout:Integer);
  var
    port, Data: string;
    start:TDatetime;
    SOData:ISuperObject;
  begin
    port := WaptGuessedIniReadString('waptservice_port', '8088');
    start := Now;
    while (Now - start)*24*60 < timeout do
    try
      Data := httpGetString('http://127.0.0.1:' + port + '/tasks.json');
      SOData := SO(Data);
      If SOData = Nil then
        Break;
      if (SOData<>Nil) and (ObjectIsNull(SOData['running']) and (SOData.A['pending'].Length=0)) then
        Break;
      Write('Waiting pending tasks to complete for '+FloatToStr(int(timeout*60 - (Now - start)*24*60*60))+'sec'#13);
      Sleep(3000);
    except
      on E:Exception do
      begin
        Writeln('Unable to speak with waptservice... continue ('+E.Message+')');
        Break;
      end;
    end;
    Writeln();
  end;

  // Trigger a local update of available packages. (require local service to be running)
  function UpdateStatus(notify_server:Boolean): ansistring;
  var
    port, Data, notify: string;
  begin
    port := WaptGuessedIniReadString('waptservice_port', '8088');
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
    Result := WaptGuessedIniReadString('repo_url', '');
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
  waptsetupPath, localVersion, requiredVersion, getVersion: ansistring;
  res: ansistring;
  waptdeploy, waptsetupurl, hashString: ansistring;

{$R *.res}

const
  defaultwapt: ansistring = 'wapt';
  minversion: ansistring = '1.5.0.12';
  _mainrepo: ansistring = '';
  wait_minutes: integer = 0;
  isTemporary: Boolean = False;

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

// remove schudled task if still
procedure DeleteFullWaptUpgradeTask;
var
  status:Integer;
begin
  RunTask('schtasks /Delete /TN fullwaptupgrade /F',status);
end;

function wget_retry(waptsetupurl, waptsetupPath:String):boolean;
var
  retryCount:integer;
  headers:String;
begin
  retryCount := 5;
  while retryCount>0 do
  try
    Writeln('Trying to reach '+waptsetupurl+'...');
    headers := httpGetHeaders(waptsetupurl,True);
    Writeln('Reachable, downloading...');
    result := wget(waptsetupurl, waptsetupPath,Nil,Nil,True,True);
    Writeln('Done.');
    break;
  except
    on E:EHTTPException do
    begin
      Writeln('Error trying to get '+waptsetupurl+' : '+E.Message+'... sleeping');
      dec(retryCount);
      if retryCount <= 0 then
        raise
      else
        Sleep(5000);
    end;
  end;
end;


begin
  cmdparams := CommandParams;
  cmdoptions := CommandOptions;

  if cmdoptions.AsObject.Exists('help') or cmdoptions.AsObject.Exists('h') then
  begin
    Writeln(rsUsage1);
    Writeln(Format(rsUsage2, [minversion]));
    Writeln(Format(rsUsage3, [defaultwapt]));
    Writeln(rsUsage4);
    Writeln(rsUsage5);
    Writeln(rsUsage6);
    Writeln(rsUsage7);
    Writeln(rsUsage8);
    Writeln(rsUsage9);
    Exit;
  end;

  isTemporary := cmdoptions.AsObject.Exists('temporary');

  if ProcessExists('waptdeploy.exe') then
  begin
    WriteLn('A waptdeploy process is already running. Aborting');
    ExitCode:=11;
    Exit;
  end;

  if ProcessExists('waptagent.exe') then
  begin
    WriteLn('A waptagent process is already running. Aborting');
    ExitCode:=11;
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

  if cmdoptions.AsObject.Exists('wait') then
    wait_minutes := cmdoptions.I['wait'];

  hashString := '';
  if cmdoptions.AsObject.Exists('hash') then
    hashString := cmdoptions.S['hash'];

  mergetasks := 'useWaptServer';
  if cmdoptions.AsObject.Exists('tasks') then
    mergetasks := cmdoptions.S['tasks'];

  waptsetupurl := '';
  writeln('WAPT version: ' + localVersion);

  if (requiredVersion = '') then
      requiredVersion := minversion;

  writeln('WAPT required version: ' + requiredVersion);
  if (localVersion = '') or (CompareVersion(localVersion, requiredVersion) < 0) or
    (requiredVersion = 'force') then
    try
      if cmdoptions.AsObject.Exists('waptsetupurl') then
        waptsetupurl := cmdoptions.S['waptsetupurl'] ;

      if waptsetupurl='' then
        waptsetupurl := mainrepo + '/waptagent.exe';

      if pos('http',waptsetupurl)=1 then
      begin
        // http mode
        isTemporary := True;
        waptsetupPath := IncludeTrailingPathDelimiter(GetTempDir)+'waptagent.exe';
        Writeln('Wapt agent path: ' + waptsetupPath);
        writeln('Wget new waptagent from ' + waptsetupurl);
        wget_retry(waptsetupurl, waptsetupPath);
      end
      else
      begin
        //file mode
        if FileExists(waptsetupurl) then
          waptsetupPath := ExpandFileName(waptsetupurl)
        else
          waptsetupPath := ExpandFileName(IncludeTrailingPathDelimiter(ExtractFileDir(paramstr(0)))+waptsetupurl);

        Writeln('Wapt agent local path: ' + waptsetupPath);
      end;

      if (hashString='') and FileExists(WaptGuessBaseDir+'\waptupgrade\waptagent.sha256') then
      begin
        writeln('Got hash from '+ WaptGuessBaseDir+'\waptupgrade\waptagent.sha256');
        hashString:=StrSplit(FileToString(WaptGuessBaseDir+'\waptupgrade\waptagent.sha256'),' ')[0];
      end;

      if (HashString <> '')then
      begin
        setuphash:=SHA256Hash(waptsetupPath);
        Writeln('SHA256 hash of downloaded setup file: '+setuphash);
        if setuphash<>hashString then
        begin
          WriteLn(rsHashError);
          ExitCode:=10;
          Exit;
        end
        else
          WriteLn('OK : Hash of waptagent match expected hash.');
      end
      else
      begin
        Writeln('ERROR: No hash provided to check waptagent.exe. either put the sha256 hash in command line or in c:\wapt\waptupgrade\waptagent.sha256');
        ExitCode:=10;
        Exit;
      end;

      getVersion := GetApplicationVersion(waptsetupPath);
      writeln('Got version: ' + getVersion);
      if (requiredVersion = 'force') or
        (CompareVersion(getVersion, requiredVersion) >= 0) then
      begin
        if wait_minutes>0 then
          WaitPendingTasks(wait_minutes);

        setupcmdline:=waptsetupPath + ' /VERYSILENT /MERGETASKS=""' + mergetasks + '""';
        writeln(Format(rsInstall,[setupcmdline]));
        res := '';
        writeln('Launching '+setupcmdline);
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
      if FileExists(waptsetupPath) and IsTemporary then
        DeleteFile(waptsetupPath);
      if isTemporary then
        DeleteFullWaptUpgradeTask;
      UpdateStatus(True);
    end
  else
  begin
    writeln(rsNothingToDo);
    writeln('Update host status on the server');
    UpdateStatus(False);
  end;

end.
