program waptdeploy;
{$mode delphiunicode}

uses classes, windows, SysUtils, wininet, URIParser, superobject , shellapi,
  tishttp, uwaptdeployres;

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

function ReadRegEntry(strSubKey,strValueName: AnsiString): AnsiString;
var
 Key: HKey;
 subkey : PAnsiChar;
 Buffer: array[0..255] of ansichar;
 Size: cardinal;
begin
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

function LocalWaptVersion:AnsiString;
var
  local_version: Ansistring;
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

function SetToIgnoreCerticateErrors(oRequestHandle:HINTERNET; var aErrorMsg: Ansistring): Boolean;
var
  vDWFlags: DWord;
  vDWFlagsLen: DWord;
begin
  Result := False;
  try
    vDWFlagsLen := SizeOf(vDWFlags);
    if not InternetQueryOption(oRequestHandle, INTERNET_OPTION_SECURITY_FLAGS, @vDWFlags, vDWFlagsLen) then begin
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


function StrToken(var S: Ansistring; Separator: AnsiString): Ansistring;
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

function ComputerSystem: ISuperObject;
var
  Res:AnsiString;
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
  res:AnsiString;
begin
  if GetDosOutput('wmic NICCONFIG where ipenabled=True get MACAddress, DefaultIPGateway, IPAddress, IPSubnet, DNSHostName, DNSDomain /VALUE','',res) then
  begin
    Result := DecodeKeyValue(res);
    //WriteLn(Result.AsJSon(True));
  end
  else
    Result := SO(stArray);
end;

function UpdateStatus:AnsiString;
var
  data:String;
begin
  data := httpGetString('http://127.0.0.1:8088/update.json');
  result := data;
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

function killtask(exename:AnsiString):AnsiString;
var
    Res :AnsiString;
begin
  if GetDosOutput('taskkill /F /IM '+exename+ ' /T','',res) then
    Result := res
  else
    Res:= '';
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

var
  tmpDir,waptsetupPath,localVersion,requiredVersion,getVersion:AnsiString;
  res : AnsiString;
  waptdeploy,waptsetupurl:AnsiString;
{$R *.res}

const
  defaultwapt:AnsiString='wapt';
  minversion:AnsiString='0.9.5.1';


begin
  if ParamStr(1)='--help'  then
  begin
      Writeln(rsUsage1);
      Writeln(Format(rsUsage2, [minversion]));
      Writeln(Format(rsUsage3, [defaultwapt]));
      Writeln(rsUsage4);
      Exit;
  end;
  waptsetupurl := 'http://'+defaultwapt+'/wapt/waptagent.exe';
  if ParamStr(1)='force' then
  begin
    localVersion := '';
    requiredVersion :='force';
  end
  else
   begin
    localVersion := LocalWaptVersion;
    requiredVersion := ParamStr(1);
  end;
  writeln('WAPT version: '+localVersion);
  if (requiredVersion='') or (requiredVersion='force') then
  begin
    requiredVersion:=minversion;
    try
      waptdeploy := httpGetString('http://'+defaultwapt+'/wapt/waptdeploy.version');
      waptdeploy := StringReplace(waptdeploy,#13#10,#10,[rfReplaceAll]);
      requiredVersion:=trim(StrToken(waptdeploy,#10));
      if requiredVersion='' then
        requiredVersion:=minversion;
      waptsetupurl :=trim(StrToken(waptdeploy,#10));
      if waptsetupurl='' then
          waptsetupurl := 'http://wapt/wapt/waptagent.exe';
      writeln('Got waptdeploy.version');
      writeln('   required version:'+requiredVersion);
      writeln('   download URL :'+waptsetupurl);
    except
      requiredVersion:=minversion;
      waptsetupurl := 'http://'+defaultwapt+'/wapt/waptagent.exe';
    end;
  end;
  writeln('WAPT required version: '+requiredVersion);
  if (localVersion='') or (CompareVersion(localVersion,requiredVersion)<0) or (requiredVersion='force') then
  try
    tmpDir := GetUniqueTempdir('wapt');
    mkdir(tmpDir);
    waptsetupPath := tmpDir+'\waptagent.exe';
    Writeln('Wapt agent path: '+waptsetupPath);
    writeln('Wget new waptagent '+ waptsetupurl);
    wget(waptsetupurl,waptsetupPath);
    getVersion:=GetApplicationVersion(waptsetupPath);
    writeln('Got version: '+getVersion);
    if (requiredVersion='force') or (CompareVersion(getVersion,requiredVersion)>=0) then
    begin
      writeln(rsInstall);

      //writeln(Sto_RedirectedExecute(waptsetupPath+' /VERYSILENT /MERGETASKS=""useWaptServer,autorunTray','',100000,'Administrateur','','.....'));
      if GetDosOutput(waptsetupPath+' /VERYSILENT /MERGETASKS=""useWaptServer""','',res) then
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

