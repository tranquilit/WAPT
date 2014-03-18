program waptdeploy;
uses classes,windows,SysUtils,wininet,URIParser,superobject;

function GetComputerName : AnsiString;
var
  buffer: array[0..255] of char;
  size: dword;
begin
  size := 256;
  if windows.GetComputerName(@buffer, size) then
    Result := buffer
  else
    Result := ''
end;

function ReadRegEntry(strSubKey,strValueName: String): String;
var
 Key: HKey;
 subkey : PChar;
 Buffer: array[0..255] of char;
 Size: cardinal;
begin
 Result := 'ERROR';
 Size := SizeOf(Buffer);
 subkey:= PChar(strSubKey);
 if RegOpenKeyEx(HKEY_LOCAL_MACHINE,
    subkey, 0, KEY_READ, Key) = ERROR_SUCCESS then
 try
    if RegQueryValueEx(Key,PChar(strValueName),nil,nil,
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


function GetApplicationVersion(Filename:Utf8String=''): Utf8String;
var
	dwHandle, dwVersionSize : DWORD;
	strSubBlock             : String;
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
				 if GetFileVersionInfo( PChar( FileName ),             // pointer to filename string
																dwHandle,                      // ignored
																dwVersionSize,                 // size of buffer
																pTemp ) then                   // pointer to buffer to receive file-version info.

						if VerQueryValue( pTemp,                           // pBlock     - address of buffer for version resource
															PChar( strSubBlock ),            // lpSubBlock - address of value to retrieve
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

function LocalWaptVersion:String;
var
  local_version: string;
begin
 result :='';
  try
    result := ReadRegEntry('SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WAPT_is1','DisplayVersion');
  except
    try
      result := ReadRegEntry('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WAPT_is1','DisplayVersion');
    except
      Result := '';
    end;
  end;
end;

function GetWinInetError(ErrorCode:Cardinal): string;
const
   winetdll = 'wininet.dll';
var
  Len: Integer;
  Buffer: PChar;
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

function SetToIgnoreCerticateErrors(oRequestHandle:HINTERNET; var aErrorMsg: string): Boolean;
var
  vDWFlags: DWord;
  vDWFlagsLen: DWord;
begin
  Result := False;
  try
    vDWFlagsLen := SizeOf(vDWFlags);
    if not InternetQueryOption(oRequestHandle, INTERNET_OPTION_SECURITY_FLAGS, @vDWFlags, vDWFlagsLen) then begin
      aErrorMsg := 'Internal error in SetToIgnoreCerticateErrors when trying to get wininet flags.' + GetWininetError(GetLastError);
      Exit;
    end;
    vDWFlags := vDWFlags or SECURITY_FLAG_IGNORE_UNKNOWN_CA or SECURITY_FLAG_IGNORE_CERT_DATE_INVALID or SECURITY_FLAG_IGNORE_CERT_CN_INVALID or SECURITY_FLAG_IGNORE_REVOCATION;
    if not InternetSetOption(oRequestHandle, INTERNET_OPTION_SECURITY_FLAGS, @vDWFlags, vDWFlagsLen) then begin
      aErrorMsg := 'Internal error in SetToIgnoreCerticateErrors when trying to set wininet INTERNET_OPTION_SECURITY_FLAGS flag .' + GetWininetError(GetLastError);
      Exit;
    end;
    Result := True;
  except
    on E: Exception do begin
      aErrorMsg := 'Unknown error in SetToIgnoreCerticateErrors.' + E.Message;
    end;
  end;
end;

function wget(const fileURL, DestFileName: Utf8String):boolean;
 const
   BufferSize = 1024*512;
 var
   hSession, hURL: HInternet;
   Buffer: array[1..BufferSize] of Byte;
   BufferLen: DWORD;
   f: File;
   sAppName: Utf8string;
   Size: Integer;
   total:DWORD;
   totalLen:DWORD;
   dwindex: cardinal;
   dwcode : array[1..20] of char;
   dwCodeLen : DWORD;
   res : PChar;
begin
  result := false;
  sAppName := ExtractFileName(ParamStr(0)) ;
  hSession := InternetOpenW(PWideChar(UTF8Decode(sAppName)), INTERNET_OPEN_TYPE_DIRECT, nil, nil, 0) ;
  try
    hURL := InternetOpenUrlW(hSession, PWideChar(UTF8Decode(fileURL)), nil, 0, INTERNET_FLAG_RELOAD+INTERNET_FLAG_PRAGMA_NOCACHE+INTERNET_FLAG_KEEP_CONNECTION, 0) ;
    if assigned(hURL) then
    try
      dwIndex  := 0;
      dwCodeLen := SizeOf(dwcode);
      totalLen := SizeOf(totalLen);
      HttpQueryInfo(hURL, HTTP_QUERY_STATUS_CODE, @dwcode, dwcodeLen, dwIndex);
      HttpQueryInfo(hURL, HTTP_QUERY_CONTENT_LENGTH or HTTP_QUERY_FLAG_NUMBER, @total,totalLen, dwIndex);
      res := pchar(@dwcode);
      if (res ='200') or (res ='302') then
      begin
        Size:=0;
        try
          AssignFile(f, UTF8Decode(DestFileName)) ;
          try
            Rewrite(f,1) ;
            repeat
              BufferLen:= 0;
              if InternetReadFile(hURL, @Buffer, SizeOf(Buffer), BufferLen) then
              begin
                inc(Size,BufferLen);
                BlockWrite(f, Buffer, BufferLen);
              end;
            until BufferLen = 0;
          finally
            CloseFile(f);
          end;

        except
          If FileExists(DestFileName) then
            SysUtils.DeleteFile(DestFileName);
          raise;
        end;
        result := (Size>0);
      end
      else
        raise Exception.Create('Unable to download: "'+fileURL+'", HTTP Status:'+res);
    finally
      InternetCloseHandle(hURL)
    end
    else
      raise Exception.Create('Unable to reach: "'+fileURL+'"');
  finally
    InternetCloseHandle(hSession)
  end
end;

function GetUniqueTempdir(Prefix: String): String;
var
  I: Integer;
  Start: String;
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

// récupère une chaine de caractères en http en utilisant l'API windows
function httpGetString(url: string; enableProxy:Boolean= False;
   ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000):Utf8String;
var
  hInet,hFile,hConnect: HINTERNET;
  buffer: array[1..1024] of byte;
  flags,bytesRead,dwError : DWORD;
  pos:integer;
  dwindex,dwcodelen,dwread,dwNumber: cardinal;
  dwcode : array[1..20] of char;
  res    : pchar;
  doc,error: String;
  uri : TURI;

begin
  result := '';
  hInet:=Nil;
  hConnect := Nil;
  hFile:=Nil;
  if enableProxy then
     hInet := InternetOpen('wapt',INTERNET_OPEN_TYPE_PRECONFIG,nil,nil,0)
  else
     hInet := InternetOpen('wapt',INTERNET_OPEN_TYPE_DIRECT,nil,nil,0);
  try
    InternetSetOption(hInet,INTERNET_OPTION_CONNECT_TIMEOUT,@ConnectTimeout,sizeof(integer));
    InternetSetOption(hInet,INTERNET_OPTION_SEND_TIMEOUT,@SendTimeOut,sizeof(integer));
    InternetSetOption(hInet,INTERNET_OPTION_RECEIVE_TIMEOUT,@ReceiveTimeOut,sizeof(integer));
    uri := ParseURI(url,'http',80);

    hConnect := InternetConnect(hInet, PChar(uri.Host), uri.port, nil, nil, INTERNET_SERVICE_HTTP, 0, 0);
    if not Assigned(hConnect) then
      Raise Exception.Create('Unable to connect to '+url+' code : '+IntToStr(GetLastError)+' ('+GetWinInetError(GetlastError)+')');
    flags := INTERNET_FLAG_NO_CACHE_WRITE or INTERNET_FLAG_PRAGMA_NOCACHE or INTERNET_FLAG_RELOAD;
    if uri.Protocol='https' then
      flags := flags or INTERNET_FLAG_SECURE;
    doc := uri.Path+uri.document;
    if uri.params<>'' then
      doc:= doc+'?'+uri.Params;
    hFile := HttpOpenRequest(hConnect, 'GET', PChar(doc), HTTP_VERSION, nil, nil,flags , 0);
    if not Assigned(hFile) then
      Raise Exception.Create('Unable to get doc '+url+' code : '+IntToStr(GetLastError)+' ('+GetWinInetError(GetlastError)+')');

    if not HttpSendRequest(hFile, nil, 0, nil, 0) then
    begin
      ErrorCode:=GetLastError;
      if (ErrorCode = ERROR_INTERNET_INVALID_CA) then
      begin
        SetToIgnoreCerticateErrors(hFile, url);
        if not HttpSendRequest(hFile, nil, 0, nil, 0) then
          Raise Exception.Create('Unable to send request to '+url+' code : '+IntToStr(GetLastError)+' ('+GetWinInetError(GetlastError)+')');
      end;
    end;

    if Assigned(hFile) then
    try
      dwIndex  := 0;
      dwCodeLen := 10;
      if HttpQueryInfo(hFile, HTTP_QUERY_STATUS_CODE, @dwcode, dwcodeLen, dwIndex) then
      begin
        res := pchar(@dwcode);
        dwNumber := sizeof(Buffer)-1;
        if (res ='200') or (res ='302') then
        begin
          Result:='';
          pos:=1;
          repeat
            FillChar(buffer,SizeOf(buffer),0);
            InternetReadFile(hFile,@buffer,SizeOf(buffer),bytesRead);
            SetLength(Result,Length(result)+bytesRead+1);
            Move(Buffer,Result[pos],bytesRead);
            inc(pos,bytesRead);
          until bytesRead = 0;
        end
        else
           raise Exception.Create('Unable to download: '+URL+' HTTP Status: '+res);
      end
      else
         raise Exception.Create('Unable to download: '+URL+' code : '+IntToStr(GetLastError)+' ('+GetWinInetError(GetlastError)+')');
    finally
      if Assigned(hFile) then
        InternetCloseHandle(hFile);
    end
    else
       raise Exception.Create('Unable to download: "'+URL+' code : '+IntToStr(GetLastError)+' ('+GetWinInetError(GetlastError)+')');

  finally
    if Assigned(hConnect) then
      InternetCloseHandle(hConnect);
    if Assigned(hInet) then
      InternetCloseHandle(hInet);
  end;
end;

function httpPostData(const UserAgent: string; const url: string; const Data: AnsiString; enableProxy:Boolean= False;
   ConnectTimeout:integer=4000;SendTimeOut:integer=60000;ReceiveTimeOut:integer=60000):Utf8String;
var
  hInet: HINTERNET;
  hHTTP: HINTERNET;
  hReq: HINTERNET;
  uri:TURI;
  pdata:String;

  buffer: array[1..1024] of byte;
  flags,bytesRead,dwError : DWORD;
  pos:integer;
  dwindex,dwcodelen,dwread,dwNumber: cardinal;
  dwcode : array[1..20] of char;
  res    : pchar;

  timeout:integer;
//  doc,error: String;
//  uri :TIdURI;


const
  wall : WideString = '*/*';
  accept: packed array[0..1] of LPWSTR = (@wall, nil);
  header: string = 'Content-Type: application/json';
begin
  uri := ParseURI(url);
  try
    if enableProxy then
       hInet := InternetOpen(PChar(UserAgent),INTERNET_OPEN_TYPE_PRECONFIG,nil,nil,0)
    else
       hInet := InternetOpen(PChar(UserAgent),INTERNET_OPEN_TYPE_DIRECT,nil,nil,0);
    try
      InternetSetOption(hInet,INTERNET_OPTION_CONNECT_TIMEOUT,@ConnectTimeout,sizeof(integer));
      InternetSetOption(hInet,INTERNET_OPTION_SEND_TIMEOUT,@SendTimeOut,sizeof(integer));
      InternetSetOption(hInet,INTERNET_OPTION_RECEIVE_TIMEOUT,@ReceiveTimeOut,sizeof(integer));

      hHTTP := InternetConnect(hInet, PChar(uri.Host), uri.Port, PCHAR(uri.Username),PCHAR(uri.Password), INTERNET_SERVICE_HTTP, 0, 1);
      if hHTTP =Nil then
          Raise Exception.Create('Unable to connect to '+url+' code: '+IntToStr(GetLastError)+' ('+UTF8Encode(GetWinInetError(GetlastError))+')');
      try
        hReq := HttpOpenRequest(hHTTP, PChar('POST'), PChar(uri.Document), nil, nil, @accept, 0, 1);
        if hReq=Nil then
            Raise Exception.Create('Unable to POST to: '+url+' code: '+IntToStr(GetLastError)+' ('+UTF8Encode(GetWinInetError(GetlastError))+')');
        try
          pdata := Data;
          if not HttpSendRequest(hReq, PChar(header), length(header), PChar(pdata), length(pdata)) then
             Raise Exception.Create('Unable to send data to: '+url+' code: '+IntToStr(GetLastError)+' ('+UTF8Encode(GetWinInetError(GetlastError))+')');

          dwIndex  := 0;
          dwCodeLen := 10;
          if HttpQueryInfo(hReq, HTTP_QUERY_STATUS_CODE, @dwcode, dwcodeLen, dwIndex) then
          begin
            res := pchar(@dwcode);
            dwNumber := sizeof(Buffer)-1;
            if (res ='200') or (res ='302') then
            begin
              Result:='';
              pos:=1;
              repeat
                FillChar(buffer,SizeOf(buffer),0);
                InternetReadFile(hReq,@buffer,SizeOf(buffer),bytesRead);
                SetLength(Result,Length(result)+bytesRead+1);
                Move(Buffer,Result[pos],bytesRead);
                inc(pos,bytesRead);
              until bytesRead = 0;
            end
            else
               raise Exception.Create('Unable to get return data for: '+URL+' HTTP Status: '+res);
          end
          else
              Raise Exception.Create('Unable to get http status for: '+url+' code: '+IntToStr(GetLastError)+' ('+UTF8Encode(GetWinInetError(GetlastError))+')');

        finally
          InternetCloseHandle(hReq);
        end;
      finally
        InternetCloseHandle(hHTTP);
      end;
    finally
      InternetCloseHandle(hInet);
    end;
  finally
  end;
end;


function StrToken(var S: string; Separator: String): string;
var
  I: SizeInt;
begin
  I := Pos(Separator, S);
  if I <> 0 then
  begin
    Result := Copy(S, 1, I - 1);
    Delete(S, 1, I);
  end
  else
  begin
    Result := S;
    S := '';
  end;
end;


  function GetDosOutput(const CommandLine: string;
     WorkDir: string;
     var text: String): Boolean;
  var
     SA: TSecurityAttributes;
     SI: TStartupInfo;
     PI: TProcessInformation;
     StdOutPipeRead, StdOutPipeWrite: THandle;
     WasOK: Boolean;
     Buffer: array[0..255] of Char;
     BytesRead: Cardinal;
     Line: String;
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
         PChar(CommandLine),
         nil,
         nil,
         True,
         0,
         nil,
         PChar(WorkDir),
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
               // finish buffer to PChar
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


function CompareVersion(v1,v2:String):integer;
var
  tok1,tok2:String;
begin
  repeat
    tok1 := StrToken(v1,'.');
    tok2 := StrToken(v2,'.');
    result := CompareStr(tok1,tok2);
    if (result<>0) or (tok1='') or (tok2='') then
      break;
  until (result<>0) or (tok1='') or (tok2='');
end;

function DecodeKeyValue(wmivalue:String;LowerKey:Boolean=True;ConvertArrayValue:Boolean=True):ISuperObject;
var
  line,key,value:String;
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

function ComputerSystem: ISuperObject;
var
  Res:String;
begin
  if GetDosOutput('wmic PATH Win32_ComputerSystemProduct GET UUID,IdentifyingNumber,Name,Vendor /VALUE','',res) then
//  if ExecAndCapture('wmic PATH Win32_ComputerSystemProduct GET UUID',res)>0 then
  begin
    Result := DecodeKeyValue(res);
    if Result.DataType=stArray then
      Result := Result.AsArray[0];
    {UUID=4C4C4544-004E-3510-8051-C7C04F325131}
  end
  else
    Result:=SO();
end;

function NetworkConfig:ISUperObject;
var
  res:String;
begin
  if GetDosOutput('wmic NICCONFIG where ipenabled=True get MACAddress, DefaultIPGateway, IPAddress, IPSubnet, DNSHostName, DNSDomain /VALUE','',res) then
  begin
    Result := DecodeKeyValue(res);
    //WriteLn(Result.AsJSon(True));
  end
  else
    Result := SO(stArray);
end;

function UpdateStatus:ISuperObject;
var
  data:String;
begin
  data := httpGetString('http://127.0.0.1:8088/update.json');
  result := SO(data);
end;

function BasicRegisterComputer:ISuperObject;
var
  json : String;
  data,nw,intf,computer: ISuperObject;

  procedure addkey(key,value:String);
  begin
    json := json+Format('"%s":"%s",',[key,value]);
  end;

begin
  data := SO;
  computer := ComputerSystem;
  data.S['uuid'] := computer.S['uuid'];
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
  result:=SO(httpPostData('waptdeploy','http://wapt:8080/add_host',
          data.AsJSon));
end;

var
  tmpDir,waptsetupPath,localVersion,requiredVersion,getVersion:String;
  res : String;
{$R *.res}

begin
  localVersion := LocalWaptVersion;
  writeln('WAPT version: '+localVersion);
  requiredVersion := ParamStr(1);
  if requiredVersion='' then
  begin
    try
      requiredVersion := httpGetString('http://wapt/wapt/waptsetup.version');
      if requiredVersion='' then
        requiredVersion:='0.8.0';
    except
      requiredVersion:='0.8.0';
    end;
  end;
  writeln('WAPT required version: '+requiredVersion);
  if (localVersion='') or (CompareVersion(localVersion,requiredVersion)<0) then
  try
    tmpDir := GetUniqueTempdir('wapt');
    mkdir(tmpDir);
    waptsetupPath := tmpDir+'\waptsetup.exe';
    Writeln('Wapt setup path: '+waptsetupPath);
    writeln('Wget new waptsetup');
    wget('http://wapt/wapt/waptsetup.exe',waptsetupPath);
    getVersion:=GetApplicationVersion(waptsetupPath);
    writeln('Got version: '+getVersion);
    if CompareVersion(getVersion,requiredVersion)>=0 then
    begin
      writeln('Install ...');
      if GetDosOutput(waptsetupPath+' /VERYSILENT /MERGETASKS=""useWaptServer,autorunTray','',res) then
        writeln('Install OK:'+LocalWaptVersion);
        //writeln(RegisterComputer.AsJSon(True));
        //writeln(UpdateStatus.AsJSon(True));
    end
    else
      writeln('Got a waptsetup version older than required version');
  finally
    writeln('Cleanup...');
    if DirectoryExists(tmpDir) then
    begin
      DeleteFile(waptsetupPath);
      RemoveDirectory(pchar(tmpDir));
    end;
  end
  else
    writeln('Nothing to do');
  writeln(UpdateStatus.AsJSon(True));
end.

