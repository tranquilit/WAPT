program waptdeploy;
{$mode delphiunicode}

uses classes, windows, SysUtils, wininet, superobject, shellapi,
  tishttp, uwaptdeployres, DCPsha256,winsock2,jwawindns,synautil,
  IniFiles;


function IniReadString(const FileName, Section, Line: string; Default: String
  ): string;
var
  Ini: TIniFile;
begin
  Ini := TIniFile.Create(FileName);
  try
    Result := Ini.ReadString(Section, Line, Default);
  finally
    Ini.Free;
  end;
end;

function GetComputerName : AnsiString;
var
  buffer: array[0..255] of ansichar;
  size: dword;
begin
  size := 256;
  if windows.GetComputerName(@buffer, size) then
    Result := buffer
  else
    Result := ''
end;

procedure SortByFields(SOArray: ISuperObject;Fields:array of string);
  function SOCompareFields(SOArray:ISuperObject;idx1,idx2:integer):integer;
  var
    compresult : TSuperCompareResult;
    SO1,SO2,F1,F2:ISuperObject;
    i:integer;
  begin
    SO1 := SOArray.AsArray[idx1];
    SO2 := SOArray.AsArray[idx2];
    for i:=low(Fields) to high(fields) do
    begin
      F1 := SO1[Fields[i]];
      F2 := SO2[Fields[i]];
      compresult := SO1.Compare(SO2);
      case compresult of
        cpLess : Result := -1;
        cpEqu  : Result := 0;
        cpGreat : Result := 1;
        cpError :  Result := CompareStr(F1.AsString,F2.AsString);
      end;
      if Result<>0 then
        Break;
    end;
  end;

  procedure QuickSort(L, R: integer);
  var
    I, J, P: Integer;
    item1,item2:ISuperObject;
  begin
    repeat
      I := L;
      J := R;
      P := (L + R) shr 1;
      repeat
        while SOCompareFields(SOArray, I, P) < 0 do Inc(I);
        while SOCompareFields(SOArray,J, P) > 0 do Dec(J);
        if I <= J then
        begin
          //exchange items
          item1 := SOArray.AsArray[I];
          item2 := SOArray.AsArray[J];
          SOArray.AsArray[I] := item2;
          SOArray.AsArray[J] := item1;
          if P = I then
            P := J
          else if P = J then
            P := I;
          Inc(I);
          Dec(J);
        end;
      until I > J;
      if L < J then QuickSort(L, J);
      L := I;
    until I >= R;
  end;

begin
  if SOArray.AsArray<>Nil then
    QuickSort(0,SOArray.AsArray.Length-1);
end;

function ReadRegEntry(strSubKey,strValueName: AnsiString): AnsiString;
var
 Key: HKey;
 subkey : PAnsiChar;
 Buffer: array[0..255] of ansichar;
 Size: cardinal;
begin
 Key := 0;
 Result := 'ERROR';
 Size := SizeOf(Buffer);
 subkey:= PAnsiChar(strSubKey);
 if RegOpenKeyEx(HKEY_LOCAL_MACHINE,
    subkey, 0, KEY_READ, Key) = ERROR_SUCCESS then
 try
    if RegQueryValueEx(Key,PAnsiChar(strValueName),nil,nil,
        @Buffer,@Size) = ERROR_SUCCESS then
      Result := Buffer;
 finally
    RegCloseKey(Key);
 end
 else
  Raise Exception.Create('Wrong key HKLM\'+strSubKey);
end;


 type
	PFixedFileInfo = ^TFixedFileInfo;
	TFixedFileInfo = record
		 dwSignature       : DWORD;
		 dwStrucVersion    : DWORD;
		 wFileVersionMS    : WORD;  // Minor Version
		 wFileVersionLS    : WORD;  // Major Version
		 wProductVersionMS : WORD;  // Build Number
		 wProductVersionLS : WORD;  // Release Version
		 dwFileFlagsMask   : DWORD;
		 dwFileFlags       : DWORD;
		 dwFileOS          : DWORD;
		 dwFileType        : DWORD;
		 dwFileSubtype     : DWORD;
		 dwFileDateMS      : DWORD;
		 dwFileDateLS      : DWORD;
	end; // TFixedFileInfo


function GetApplicationVersion(Filename:AnsiString=''): AnsiString;
var
	dwHandle, dwVersionSize : DWORD;
	strSubBlock             : AnsiString;
	pTemp                   : Pointer;
	pData                   : Pointer;
begin
  Result:='';
	if Filename='' then
    FileName:=ParamStr(0);
	 strSubBlock := '\';

	 // get version information values
	 dwVersionSize := GetFileVersionInfoSizeW( PWideChar( UTF8Decode(FileName) ), // pointer to filename string
																						dwHandle );        // pointer to variable to receive zero

	 // if GetFileVersionInfoSize is successful
	 if dwVersionSize <> 0 then
	 begin
			GetMem( pTemp, dwVersionSize );
			try
				 if GetFileVersionInfo( PAnsiChar( FileName ),             // pointer to filename string
																dwHandle,                      // ignored
																dwVersionSize,                 // size of buffer
																pTemp ) then                   // pointer to buffer to receive file-version info.

						if VerQueryValue( pTemp,                           // pBlock     - address of buffer for version resource
															PAnsiChar( strSubBlock ),            // lpSubBlock - address of value to retrieve
															pData,                           // lplpBuffer - address of buffer for version pointer
															dwVersionSize ) then             // puLen      - address of version-value length buffer
							 with PFixedFileInfo( pData )^ do
								Result:=IntToSTr(wFileVersionLS)+'.'+IntToSTr(wFileVersionMS)+
											'.'+IntToStr(wProductVersionLS)+'.'+IntToStr(wProductVersionMS);
			finally
				 FreeMem( pTemp );
			end; // try
	 end; // if dwVersionSize
end;

function WaptGetIniPath:String;
begin
  if FileExists('c:\wapt\wapt-get.ini') then
    Result := 'c:\wapt\wapt-get.ini'
  else
  if FileExists(GetEnvironmentVariable('ProgramFiles(x86)')+'\wapt\wapt-get.ini') then
      Result := GetEnvironmentVariable('ProgramFiles(x86)')+'\wapt\wapt-get.ini'
  else
  if FileExists(GetEnvironmentVariable('ProgramFiles')+'\wapt\wapt-get.ini') then
      Result := GetEnvironmentVariable('ProgramFiles')+'\wapt\wapt-get.ini'
  else
    Result := 'c:\wapt\wapt-get.ini';
end;

function WaptIniReadString(Parameter,DefaultValue:String):String;
begin
  if FileExists(WaptGetIniPath) then
    Result := IniReadString(WaptGetIniPath,'global',Parameter,DefaultValue)
  else
    Result := DefaultValue;
end;

function LocalWaptVersion: ansistring;
var
  local_version: ansistring;
  i:integer;
begin
  Result := '';
  try
    local_version := ReadRegEntry(
      'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WAPT_is1',
      'DisplayVersion');
  except
    try
      local_version := ReadRegEntry(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WAPT_is1',
        'DisplayVersion');
    except
      local_version := '';
    end;
    // check if looks like actual version string.
  end;
  for i := 1 to length(local_version) do
    if CharInSet(local_version[i],['0'..'9','-','.']) then
      Result := Result + local_version[i];
end;

function GetWinInetError(ErrorCode:Cardinal): Ansistring;
const
   winetdll = 'wininet.dll';
var
  Len: Integer;
  Buffer: PAnsiChar;
begin
  Len := FormatMessage(
  FORMAT_MESSAGE_FROM_HMODULE or FORMAT_MESSAGE_FROM_SYSTEM or
  FORMAT_MESSAGE_ALLOCATE_BUFFER or FORMAT_MESSAGE_IGNORE_INSERTS or  FORMAT_MESSAGE_ARGUMENT_ARRAY,
  Pointer(GetModuleHandle(winetdll)), ErrorCode, 0, @Buffer, SizeOf(Buffer), nil);
  try
    while (Len > 0) and {$IFDEF UNICODE}(CharInSet(Buffer[Len - 1], [#0..#32, '.'])) {$ELSE}(Buffer[Len - 1] in [#0..#32, '.']) {$ENDIF} do Dec(Len);
    SetString(Result, Buffer, Len);
  finally
    LocalFree(HLOCAL(Buffer));
  end;
end;

//Configure supplied Wininet Request handle to ignore certificates errors
function SetToIgnoreCerticateErrors(oRequestHandle:HINTERNET; var aErrorMsg: Ansistring): Boolean;
var
  vDWFlags: DWord;
  vDWFlagsLen: DWord;
begin
  Result := False;
  try
    vDWFlagsLen := SizeOf(vDWFlags);
    if not InternetQueryOption(oRequestHandle, INTERNET_OPTION_SECURITY_FLAGS, @vDWFlags, vDWFlagsLen) then
    begin
      aErrorMsg := Format(rsWininetGetFlagsError, [GetWininetError(GetLastError)]);
      Exit;
    end;
    vDWFlags := vDWFlags or SECURITY_FLAG_IGNORE_UNKNOWN_CA or SECURITY_FLAG_IGNORE_CERT_DATE_INVALID or SECURITY_FLAG_IGNORE_CERT_CN_INVALID or SECURITY_FLAG_IGNORE_REVOCATION;
    if not InternetSetOption(oRequestHandle, INTERNET_OPTION_SECURITY_FLAGS, @vDWFlags, vDWFlagsLen) then begin
      aErrorMsg := Format(rsWininetSetFlagsError, [GetWininetError(GetLastError)]);
      Exit;
    end;
    Result := True;
  except
    on E: Exception do begin
      aErrorMsg := Format(rsUnknownError, [E.Message]);
    end;
  end;
end;


function GetUniqueTempdir(Prefix: AnsiString): AnsiString;
var
  I: Integer;
  Start: AnsiString;
begin
  Start:=GetTempDir;
  if (Prefix='') then
      Start:=Start+'TMP'
  else
    Start:=Start+Prefix;
  I:=0;
  repeat
    Result:=Format('%s%.5d.tmp',[Start,I]);
    Inc(I);
  until not DirectoryExists(Result);
end;


//Given a string and a separator, return next token and remove this token from start of source string.
function StrToken(var S: Ansistring; Separator: AnsiString): Ansistring;
var
  I: SizeInt;
begin
  I := Pos(Separator, S);
  if I <> 0 then
  begin
    Result := Copy(S, 1, I - 1);
    Delete(S, 1, I+length(Separator)-1);
  end
  else
  begin
    Result := S;
    S := '';
  end;
end;

// Run Commandline, return output in Text var, and retunr True is command has benn launched properly.
function GetDosOutput(const CommandLine: Ansistring;
   WorkDir: Ansistring;
   var text: AnsiString): Boolean;
var
   SA: TSecurityAttributes;
   SI: TStartupInfo;
   PI: TProcessInformation;
   StdOutPipeRead, StdOutPipeWrite: THandle;
   WasOK: Boolean;
   Buffer: array[0..255] of AnsiChar;
   BytesRead: Cardinal;
   Line: AnsiString;
begin
   with SA do
   begin
     nLength := SizeOf(SA);
     bInheritHandle := True;
     lpSecurityDescriptor := nil;
   end;
   // create pipe for standard output redirection
   CreatePipe(StdOutPipeRead, // read handle
              StdOutPipeWrite, // write handle
              @SA, // security attributes
              0 // number of bytes reserved for pipe - 0 default
              );
   try
     // Make child process use StdOutPipeWrite as standard out,
     // and make sure it does not show on screen.
     with SI do
     begin
       FillChar(SI, SizeOf(SI), 0);
       cb := SizeOf(SI);
       dwFlags := STARTF_USESHOWWINDOW or STARTF_USESTDHANDLES;
       wShowWindow := SW_HIDE;
       hStdInput := GetStdHandle(STD_INPUT_HANDLE); // don't redirect stdinput
       hStdOutput := StdOutPipeWrite;
       hStdError := StdOutPipeWrite;
     end;

     // launch the command line compiler
     //WorkDir := 'C:\';
     if workdir='' then
      workdir := GetCurrentDir;
     result := CreateProcess(
       nil,
       PAnsiChar(CommandLine),
       nil,
       nil,
       True,
       0,
       nil,
       PAnsiChar(WorkDir),
       SI,
       PI);

     // Now that the handle has been inherited, close write to be safe.
     // We don't want to read or write to it accidentally.
     CloseHandle(StdOutPipeWrite);
     // if process could be created then handle its output
     if result then
       try
         // get all output until dos app finishes
         Line := '';
         repeat
           // read block of characters (might contain carriage returns and  line feeds)
           WasOK := ReadFile(StdOutPipeRead, Buffer, 255, BytesRead, nil);

           // has anything been read?
           if BytesRead > 0 then
           begin
             // finish buffer to PAnsiChar
             Buffer[BytesRead] := #0;
             // combine the buffer with the rest of the last run
             Line := Line + Buffer;
           end;
         until not WasOK or (BytesRead = 0);
         // wait for console app to finish (should be already at this point)
         WaitForSingleObject(PI.hProcess, INFINITE);
       finally
         // Close all remaining handles
         CloseHandle(PI.hThread);
         CloseHandle(PI.hProcess);
       end;
   finally
     text := Line;
     CloseHandle(StdOutPipeRead);
   end;
end;

// Compare version member by member as int or string
function CompareVersion(v1,v2:AnsiString):integer;
var
  tok1,tok2:AnsiString;
begin
  repeat
    tok1 := StrToken(v1,'.');
    tok2 := StrToken(v2,'.');
    if (tok1<>'') and (tok2<>'') then
    try
      result := StrToInt(tok1)-StrToInt(tok2);
    except
      result := CompareStr(tok1,tok2);
    end;
    if (result<>0) or (tok1='') or (tok2='') then
      break;
  until (result<>0) or (tok1='') or (tok2='');
end;

//Decodes a string of lines like key=value as returned by wmic /VALUE command.
function DecodeKeyValue(wmivalue:AnsiString;LowerKey:Boolean=True;ConvertArrayValue:Boolean=True):ISuperObject;
var
  line,key,value:AnsiString;
  CurrObject:ISuperObject;
  isArray:Boolean;
begin
  Result :=  TSuperObject.Create(stArray);
  CurrObject := Nil;
  repeat
    line := trim(StrToken(wmivalue,#13#10));
    if line<>'' then
    begin
      if CurrObject=Nil then
      begin
        CurrObject := SO;
        Result.AsArray.Add(CurrObject);
      end;
      key := StrToken(line,'=');
      value := trim(line);
      If LowerKey then
        key := LowerCase(Key);
      If ConvertArrayValue then
      begin
        isArray:=False;
        if (value<>'') and (value[1]='{') then
        begin
          value[1] := '[';
          isArray:=True;
        end;
        if isArray and (value<>'') and (value[length(value)]='}') then
          value[length(value)] := ']';
        if isArray then
          CurrObject[key] := SO(value)
        else
          CurrObject.S[key] := value;
      end
      else
        CurrObject.S[key] := value;
    end
    else
      CurrObject := Nil;
  until trim(wmivalue)='';
end;


//Get basic identification information fir the computer using wmic
function ComputerSystem: ISuperObject;
var
  Res:AnsiString;
begin
  if GetDosOutput('wmic PATH Win32_ComputerSystemProduct GET UUID,IdentifyingNumber,Name,Vendor /VALUE','',res) then
  begin
    Result := DecodeKeyValue(res);
    if Result.DataType=stArray then
      Result := Result.AsArray[0];
    {UUID=4C4C4544-004E-3510-8051-C7C04F325131}
  end
  else
    Result:=SO();
end;

// Retrieve enabled network interfaces with ip parameters.
function NetworkConfig:ISUperObject;
var
  res:AnsiString;
begin
  if GetDosOutput('wmic NICCONFIG where ipenabled=True get MACAddress, DefaultIPGateway, IPAddress, IPSubnet, DNSHostName, DNSDomain /VALUE','',res) then
    Result := DecodeKeyValue(res)
  else
    Result := SO(stArray);
end;

// Trigger a local update of available packages. (require local service to be running)
function UpdateStatus:AnsiString;
var
  port,data:String;
begin
  port := WaptIniReadString('waptservice_port','8088');
  data := httpGetString('http://127.0.0.1:'+port+'/update.json');
  result := data;
end;


function killtask(exename:AnsiString):AnsiString;
var
    Res :AnsiString;
begin
  if GetDosOutput('taskkill /F /IM '+exename+ ' /T','',res) then
    Result := res
  else
    Res:= '';
end;

function IPV4ToString(ipv4:LongWord):String;
begin
  Result :=  format('%D.%D.%D.%D',[ipv4  and $FF, (ipv4  shr 8) and $FF,  (ipv4  shr 16) and $FF, (ipv4  shr 24) and $FF]);
end;

//query current dns server for A record and return a list of IP (recursive if cname is returned by the DNS)
function DNSAQuery(name: AnsiString): ISuperObject;
var
  ppQueryResultsSet : PDNS_RECORD;
  retvalue: Integer;
  res : AnsiString;
  ip,ips: ISuperObject;
begin
  Result := TSuperObject.Create(stArray);
  ppQueryResultsSet := Nil;
  retvalue := DnsQuery(
    PAnsiChar(name),
    DNS_TYPE_A,
    DNS_QUERY_BYPASS_CACHE or DNS_QUERY_NO_LOCAL_NAME or DNS_QUERY_NO_HOSTS_FILE,
    Nil,
    @ppQueryResultsSet,
    Nil);
  if (retvalue=0) and (ppQueryResultsSet<>Nil) then
  try
    while ppQueryResultsSet<>Nil do
    begin
      if (ppQueryResultsSet^.wType=DNS_TYPE_CNAME) then
      begin
        // recursive query if a CNAME is returned.
        // very strange ... ppQueryResultsSet^.Data.PTR works but ppQueryResultsSet^.Data.CNAME not... same structure pNameHost in both cases.
        ips := DNSAQuery(ppQueryResultsSet^.Data.PTR.pNameHost);
        for ip in ips do
          Result.AsArray.Add(ip.AsString);
      end
      else
      if (ppQueryResultsSet^.wType=DNS_TYPE_A) and (ppQueryResultsSet^.Data.A.IpAddress<>0) and (LowerCase(ppQueryResultsSet^.pName) = LowerCase(name)) then
      begin
        res := IPV4ToString(ppQueryResultsSet^.Data.A.IpAddress);
        UniqueString(res);
        Result.AsArray.Add(res);
      end;
      ppQueryResultsSet:= ppQueryResultsSet^.pNext;
    end;
  finally
    DnsRecordListFree(ppQueryResultsSet,DnsFreeRecordList);
  end;
end;

//query current dns server for SRV record and return a list of {name,priority,weight,port}
function DNSSRVQuery(name:AnsiString):ISuperObject;
var
  ppQueryResultsSet : PDNS_RECORD;
  retvalue: Integer;
  res : AnsiString;
  rec:ISuperObject;
begin
  Result := TSuperObject.Create(stArray);
  ppQueryResultsSet := Nil;
  retvalue := DnsQuery(
    PAnsiChar(name),
    DNS_TYPE_SRV,
    DNS_QUERY_BYPASS_CACHE or DNS_QUERY_NO_LOCAL_NAME or DNS_QUERY_NO_HOSTS_FILE,
    Nil,
    @ppQueryResultsSet,
    Nil);
  if (retvalue=0) and (ppQueryResultsSet<>Nil) then
  try
    while ppQueryResultsSet<>Nil do
    begin
      rec:= TSuperObject.Create(stObject);
      if ppQueryResultsSet^.wType=DNS_TYPE_SRV then
      begin
        res := ppQueryResultsSet^.Data.SRV.pNameTarget;
        UniqueString(res);
        rec.S['name'] := res;
        rec.I['port'] := ppQueryResultsSet^.Data.SRV.wPort;
        rec.I['priority'] := ppQueryResultsSet^.Data.SRV.wPriority;
        rec.I['weight'] := ppQueryResultsSet^.Data.SRV.wWeight;
        Result.AsArray.Add(rec);
      end;
      ppQueryResultsSet:= ppQueryResultsSet^.pNext;
    end;
    SortByFields(Result,['priority','port']);
  finally
    DnsRecordListFree(ppQueryResultsSet,DnsFreeRecordList);
  end;
end;

//query current dns server for CNAME record and return a list of {name}
function DNSCNAMEQuery(name:AnsiString):ISuperObject;
var
  ppQueryResultsSet : PDNS_RECORD;
  retvalue: Integer;
  res : AnsiString;
begin
  Result := TSuperObject.Create(stArray);
  ppQueryResultsSet := Nil;
  retvalue := DnsQuery(
    PAnsiChar(name),
    DNS_TYPE_CNAME,
    DNS_QUERY_BYPASS_CACHE or DNS_QUERY_NO_LOCAL_NAME or DNS_QUERY_NO_HOSTS_FILE,
    Nil,
    @ppQueryResultsSet,
    Nil);
  if (retvalue=0) and (ppQueryResultsSet<>Nil) then
  try
    while ppQueryResultsSet<>Nil do
    begin
      // strange ppQueryResultsSet^.Data.PTR works but not ppQueryResultsSet^.Data.CNAME
      if (ppQueryResultsSet^.wType=DNS_TYPE_CNAME) and (ppQueryResultsSet^.Data.PTR.pNameHost<>Nil) then
      begin
        res := ppQueryResultsSet^.Data.PTR.pNameHost;
        UniqueString(res);
        Result.AsArray.Add(res);
      end;
      ppQueryResultsSet:= ppQueryResultsSet^.pNext;
    end;
  finally
    DnsRecordListFree(ppQueryResultsSet,DnsFreeRecordList);
  end;
end;

Function IPV4ToInt(ipaddr:AnsiString):LongInt;
begin
  Result := inet_addr(PAnsiChar(ipaddr));
end;

Function SameIPV4Subnet(ip1,ip2,netmask:AnsiString):Boolean;
begin
    Result := (IPV4ToInt(ip1) and IPV4ToInt(netmask)) = (IPV4ToInt(ip2) and IPV4ToInt(netmask));
end;

//Get dns domain from global tcpip parameters in registry
function GetDNSDomain:AnsiString;
begin
  try
    Result := ReadRegEntry('SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters','Domain');
    if (Result='') or (Result = 'ERROR') then
        Result := ReadRegEntry('SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters','DhcpDomain');
  except
    Result := ReadRegEntry('SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters','DhcpDomain');
  end;
end;

function httpGetDate(url:RawByteString):TDateTime;
var
  headers,line : AnsiString;
begin
  Result := 0;
  headers:=httpGetHeaders(url);
  if headers<>'' then
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
    Headers := ReplaceString(Headers,#13#10,#13);
    while Headers<>'' do
    begin
      line := StrToken(Headers,#13);
      if pos('Last-Modified:',line)=1 then
      begin
        Result := DecodeRfcDateTime(Copy(line,pos(':',line)+2,255));
        exit;
      end;
    end;
  end;
end;


function SameNet(connected:ISuperObject;IP:AnsiString):Boolean;
var
  conn:ISuperObject;
begin
  for conn in Connected do
  begin
    //Assumed first ip is ipv4 and second is IPV6... in the wmic network value object
    if SameIPV4Subnet(conn['ipaddress'].AsArray.S[0],IP,conn['ipsubnet'].AsArray.S[0]) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

function GetMainWaptRepo: String;
var
  rec,recs,urls,ConnectedIps,ServerIp : ISuperObject;
  url,dnsdomain:AnsiString;
  PackagesDate: TDateTime;
begin
  Result := WaptIniReadString('repo_url','');
  if Result <> '' then
    exit;

  dnsdomain:=GetDNSDomain;
  if dnsdomain<>'' then
  begin
    ConnectedIps := NetworkConfig;
    //SRV _wapt._tcp
    recs := DNSSRVQuery('_wapt._tcp.'+dnsdomain);
    for rec in recs do
    begin
      if rec.I['port'] = 443 then
        url := 'https://'+rec.S['name']+'/wapt'
      else
        url := 'http://'+rec.S['name']+':'+rec.S['port']+'/wapt';
      rec.S['url'] := url;
      try
        ServerIp := DNSAQuery(rec.S['name']);
        if ServerIp.AsArray.Length > 0 then
          rec.B['outside'] := not SameNet(ConnectedIps,ServerIp.AsArray.S[0])
        else
          rec.B['outside'] := True;
      except
        rec.B['outside'] := True;
      end;
      // order is priority asc but wieght desc
      rec.I['weight'] := - rec.I['weight'];
    end;
    SortByFields(recs,['outside','priority','weight']);

    for rec in recs do
    try
      writeln('trying '+rec.S['url']+'/Packages');
      Result := rec.S['url'];
      PackagesDate:=httpGetDate(Result+'/Packages');
      if PackagesDate>0 then
        Exit;
    except
      on E:Exception do writeln('Unable to HEAD '+ rec.S['url']+'/Packages'+' '+E.Message);
    end;

    //CNAME wapt.
    recs := DNSCNAMEQuery('wapt'+dnsdomain);
    for rec in recs do
    try
      Result := 'http://'+rec.AsString+'/wapt';
      writeln('trying '+result+'/Packages');
      PackagesDate:=httpGetDate(Result+'/Packages');
      if PackagesDate>0 then
        Exit;
    except
      on E:Exception do writeln('Unable to HEAD '+ result+'/Packages'+' '+E.Message);
    end;

    //A wapt
    Result := 'http://wapt.'+dnsdomain+'/wapt';
    writeln('trying '+result+'/Packages');
    try
      PackagesDate:=httpGetDate(Result+'/Packages');
      if PackagesDate>0 then
        Exit;
    except
      on E:Exception do writeln('Unable to HEAD '+ result+'/Packages'+' '+E.Message);
    end;
  end;
  result :='';
end;

const
  CacheWaptServerUrl: AnsiString = 'None';

function GetWaptServerURL: String;
var
  dnsdomain,url:AnsiString;
  rec,recs,ConnectedIps,ServerIp : ISuperObject;

begin
  Result := WaptIniReadString('wapt_server','');
  if Result <> '' then
    exit;

  if CacheWaptServerUrl<>'None' then
  begin
    Result := CacheWaptServerUrl;
    Exit;
  end;

  ConnectedIps := NetworkConfig;
  dnsdomain:=GetDNSDomain;
  if dnsdomain<>'' then
  begin
    //SRV _wapt._tcp
    recs := DNSSRVQuery('_waptserver._tcp.'+dnsdomain);
    for rec in recs do
    begin
      if rec.I['port'] = 443 then
        url := 'https://'+rec.S['name']
      else
        url := 'http://'+rec.S['name']+':'+rec.S['port'];
      rec.S['url'] := url;
      try
        ServerIp := DNSAQuery(rec.S['name']);
        if ServerIp.AsArray.Length > 0 then
          rec.B['outside'] := not SameNet(ConnectedIps,ServerIp.AsArray.S[0])
        else
          rec.B['outside'] := True;
      except
        rec.B['outside'] := True;
      end;
      // order is priority asc but wieght desc
      rec.I['weight'] := - rec.I['weight'];
    end;
    SortByFields(recs,['outside','priority','weight']);

    for rec in recs do
    begin
      Result := rec.S['url'];
      CacheWaptServerUrl := Result;
      exit;
    end;
  end;

  //None found by DNS Query
  result :='';
  //Invalid cache
  CacheWaptServerUrl := 'None';
end;

// Send to the WAPT Server the minimum registration information
function BasicRegisterComputer:ISuperObject;
var
  uuid,json : String;
  data,nw,intf,computer: ISuperObject;

  procedure addkey(key,value:String);
  begin
    json := json+Format('"%s":"%s",',[key,value]);
  end;

begin
  data := SO;
  computer := ComputerSystem;
  uuid := WaptIniReadString('uuid',computer.S['uuid']);

  data.S['uuid'] := uuid;
  data.S['wapt.wapt-exe-version'] := LocalWaptVersion;
  data.S['host.computer_name'] := GetComputerName;
  data.S['host.system_productname'] := computer.S['name'];
  data.S['host.system_manufacturer'] := computer.S['vendor'];
  data.S['host.system_serialnr'] := computer.S['identifyingnumber'];
  data.S['dmi.Chassis_Information.Serial_Number'] := computer.S['identifyingnumber'];
  nw := NetworkConfig;
  for intf in nw do
  begin
    if intf.AsObject.Exists('defaultipgateway') then
    begin
     {
      "ipaddress": [
       "192.168.149.201"],
      "defaultipgateway": [
       "192.168.149.254"],
      "dnshostname": "wstestwapt",
      "ipsubnet": [
       "255.255.255.0"],
      "macaddress": "08:00:27:72:E9:E4",
      "dnsdomain": "tranquilit.local"
     }
      data.S['host.dns_domain'] := LowerCase(nw.AsArray[0].S['dnsdomain']);
      data.S['host.connected_ips'] := nw.AsArray[0].A['ipaddress'].S[0];
      data.S['host.mac'] := lowercase(nw.AsArray[0].S['macaddress']);
      data.S['host.computer_fqdn'] := lowercase(nw.AsArray[0].S['dnshostname']+'.'+nw.AsArray[0].S['dnsdomain']);
      break;
    end;
  end;
  result:=SO(httpPostData('waptdeploy',getWaptServerURL+'/add_host',
          data.AsJSon));
end;

function RunAsAdmin(const Handle: Hwnd; aFile : Ansistring; Params: Ansistring): Boolean;
var
  sei:  TSHELLEXECUTEINFO;
begin
  FillChar(sei, SizeOf(sei), 0);
  With sei do begin
     cbSize := SizeOf(sei);
     Wnd := Handle;
     fMask := SEE_MASK_FLAG_DDEWAIT or SEE_MASK_FLAG_NO_UI;
     lpVerb := 'runAs';
     lpFile := PAnsiChar(aFile);
     lpParameters := PAnsiChar(Params);
     nShow := SW_SHOWNORMAL;
  end;
  Result := ShellExecuteExA(@sei);
end;

function BinToStr(const Bin: Array of Byte): AnsiString;
const HexSymbols = '0123456789ABCDEF';
var i: Integer;
begin
  SetLength(Result, 2 * Length(Bin));
  for i := 0 to Length(Bin) - 1 do
  begin
    Result[1 + 2 * i + 0] := HexSymbols[1 + Bin[i] shr 4];
    Result[1 + 2 * i + 1] := HexSymbols[1 + Bin[i] and $0F];
  end;
end;

function SHA256VerifyFile(FilePath, Hash: AnsiString): Boolean;
var
  Context: TDCP_sha256;
  Buf: PByte;
  BufSize, ReadSize, TotalSize: Integer;
  FileStream: TFileStream;
  RawDigest: Array[0..31] of Byte;
  HexDigest: Array[0..64] of Char;
begin
  Result := False;
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

    Result := UpperCase(hash) = BinToStr(RawDigest);

  finally
    if FileStream <> nil then
      FileStream.Free;
    if Buf <> nil then
      FreeMem(Buf);
    if Context <> nil then
      Context.Free;
  end;
end;

type TStrArray = Array of AnsiString;

// Returns only non options arguments of command line (those not starting with -- or -)
function CommandParams:TStrArray;
var
  i,p:Integer;
begin
  SetLength(Result,Paramcount);
  p := 0;
  For i:=1 to Paramcount do
  begin
    if (ParamStr(i)<>'') and (ParamStr(i)[1]<>'-') then
    begin
      Result[p] := ParamStr(i);
      inc(p);
    end;
  end;
  SetLength(result,p);
end;

//Return a map of the options of command line (starting with - or --)
function CommandOptions:ISuperObject;
var
  i:integer;
  line,key,value:AnsiString;
begin
  Result := TSuperObject.Create(stObject);
  for i:=1 to Paramcount do
  begin
    line := ParamStr(i);
    if (line<>'') and (line[1]='-') then
    begin
      if pos('--',line)=1 then
      begin
        line := copy(line,3,length(line));
        key := StrToken(line,'=');
        value := line;
        Result.S[key] := value;
      end
      else
      if pos('-',line)=1 then
      begin
        line := copy(line,2,length(line));
        key := line[1];
        value := trim(copy(line,2,length(line)));
        Result.S[key] := value;
      end
    end;
  end;
end;

var
  tmpDir,waptsetupPath,localVersion,requiredVersion,getVersion:AnsiString;
  res : AnsiString;
  waptdeploy,waptsetupurl, hashString:AnsiString;
{$R *.res}

const
  defaultwapt:AnsiString='wapt';
  minversion:AnsiString='1.2.3.0';
  mainrepo:AnsiString='http://wapt/wapt';

var
  cmdparams:TStrArray;
  cmdoptions:ISuperObject;
  innotasks:String;


begin
  cmdparams := CommandParams;
  cmdoptions := CommandOptions;

  if cmdoptions.AsObject.Exists('help') or cmdoptions.AsObject.Exists('h')  then
  begin
    Writeln(rsUsage1);
    Writeln(Format(rsUsage2, [minversion]));
    Writeln(Format(rsUsage3, [defaultwapt]));
    Writeln(Format(rsUsage4, []));
    Writeln(Format(rsUsage5, []));
    Writeln(Format(rsUsage6, []));
    Writeln(Format(rsUsage7, []));
    Writeln(Format(rsUsage8, []));
    Exit;
  end;

  waptsetupurl := mainrepo+'/waptagent.exe';
  if cmdoptions.AsObject.Exists('force') then
  begin
    localVersion := '';
    requiredVersion :='force';
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
    if Length(cmdparams)>=1 then
      requiredVersion := cmdparams[0]
  end;

  hashString := '';
  if cmdoptions.AsObject.Exists('hash') then
    hashString := cmdoptions.S['hash'];

  innotasks := 'installService,installredist2008,autoUpgradePolicy';
  if cmdoptions.AsObject.Exists('tasks') then
    innotasks := cmdoptions.S['tasks'];

  waptsetupurl := '';
  writeln('WAPT version: '+localVersion);
  if (requiredVersion='') or (requiredVersion='force') then
  begin
    if cmdoptions.AsObject.Exists('repo_url') then
      mainrepo := cmdoptions.S['repo_url']
    else
    try
      mainrepo :=GetMainWaptRepo;
    except
      on E:Exception do
      begin
        Writeln('Unable to discover the wapt repository: '+E.Message);
        if GetDNSDomain<>'' then
          mainrepo := 'http://wapt.'+GetDNSDomain+'/wapt'
        else
          mainrepo := 'http://wapt/wapt';
      end;
    end;
    WriteLn('Main repo:'+mainrepo);
    requiredVersion:=minversion;
  end;

  if cmdoptions.AsObject.Exists('waptsetupurl') then
    waptsetupurl := cmdoptions.S['waptsetupurl'];

  if waptsetupurl = '' then
    waptsetupurl := mainrepo+'/waptagent.exe';

  writeln('WAPT required version: '+requiredVersion);
  if (localVersion='') or (CompareVersion(localVersion,requiredVersion)<0) or (requiredVersion='force') then
  try
    tmpDir := GetUniqueTempdir('wapt');
    mkdir(tmpDir);
    waptsetupPath := tmpDir+'\waptagent.exe';
    Writeln('Wapt agent path: '+waptsetupPath);
    writeln('Wget new waptagent '+ waptsetupurl);
    wget(waptsetupurl,waptsetupPath);

    if (HashString <> '') and (not SHA256VerifyFile(WaptSetupPath, HashString)) then
    begin
      WriteLn('Error while checking hash.');
      Exit;
    end;

    getVersion:=GetApplicationVersion(waptsetupPath);
    writeln('Got version: '+getVersion);
    if (requiredVersion='force') or (CompareVersion(getVersion,requiredVersion)>=0) then
    begin
      writeln(rsInstall);
      if GetDosOutput(waptsetupPath+' /VERYSILENT /TASKS=""'+innotasks+'""','',res) then
        writeln(Format(rsInstallOK, [LocalWaptVersion]));
    end
    else
      writeln(rsVersionError);
  finally
    writeln(rsCleanup);
    if DirectoryExists(tmpDir) then
    begin
      DeleteFile(waptsetupPath);
      RemoveDirectory(pansichar(tmpDir));
    end;
  end
  else
    writeln(rsNothingToDo);
  UpdateStatus;
end.

