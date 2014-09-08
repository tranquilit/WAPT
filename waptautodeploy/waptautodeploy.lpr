program waptautodeploy;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Classes, SysUtils,variants,windows, wininet,superobject,
  CustApp,IdURI,registry,eventlog,UnitRedirect,tisstrings;
  { you can add units after this }

type

  { Twaptautodeploy }

  Twaptautodeploy = class(TCustomApplication)
  protected
    procedure DoRun; override;
  public
    computer_fqdn,computer_name : String;
    uuid: string;
    wapt_repo,wapt_server : String;
    repo_waptsetup,local_waptsetup : String;
    setup_options : String;
    local_wapt_version:String;
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
    procedure ParseOptions;
  end;

  { utilities }
procedure log_event(type_log:String;log_message:String);
var
   log: TEventLog;
begin
  log := TEventLog.Create(Nil);
  try
    log.LogType := ltSystem;
    log.Active:= True;
    if type_log = 'warning' then
    begin
        log.Warning(log_message);
    end
    else if type_log = 'error' then
    begin
      log.Error(log_message);
    end
    else if type_log = 'info' then
    begin
      log.Info(log_message);
    end
  finally
    log.Free;
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

function httpGetString(url: string ): Utf8String;
var
  GlobalhInet,hFile,hConnect: HINTERNET;
  localFile: File;
  buffer: array[1..1024] of byte;
  flags,bytesRead,dwError,port : DWORD;
  pos:integer;
  dwindex,dwcodelen,dwread,dwNumber: cardinal;
  dwcode : array[1..20] of char;
  res    : pchar;
  doc,error: String;
  uri :TIdURI;
begin
  result := '';
  GlobalhInet:=Nil;
  hConnect := Nil;
  hFile:=Nil;
  GlobalhInet := InternetOpen('wapt',
      INTERNET_OPEN_TYPE_PRECONFIG,nil,nil,0);
  try
    uri := TIdURI.Create(url);
    BEGIN
      if uri.Port<>'' then
        port := StrToInt(uri.Port)
      else
        if (uri.Protocol='https') then
          port := INTERNET_DEFAULT_HTTPS_PORT
        else
          port := INTERNET_DEFAULT_HTTP_PORT;

      hConnect := InternetConnect(GlobalhInet, PChar(uri.Host), port, nil, nil, INTERNET_SERVICE_HTTP, 0, 0);
      flags := INTERNET_FLAG_NO_CACHE_WRITE or INTERNET_FLAG_PRAGMA_NOCACHE or INTERNET_FLAG_RELOAD;
      if uri.Protocol='https' then
        flags := flags or INTERNET_FLAG_SECURE;
      doc := uri.Path+uri.document;
      if uri.params<>'' then
        doc:= doc+'?'+uri.Params;
      hFile := HttpOpenRequest(hConnect, 'GET', PChar(doc), HTTP_VERSION, nil, nil,flags , 0);
      if not HttpSendRequest(hFile, nil, 0, nil, 0) then
      begin
        ErrorCode:=GetLastError;
        if (ErrorCode = ERROR_INTERNET_INVALID_CA) then
        begin
          SetToIgnoreCerticateErrors(hFile, url);
          if not HttpSendRequest(hFile, nil, 0, nil, 0) then
            log_event('error','Unable to send request to '+url+' error code '+IntToStr(GetLastError));
            Raise Exception.Create('Unable to send request to '+url+' error code '+IntToStr(GetLastError));

        end;
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
        begin
           log_event('error','Unable to download: '+URL+#13#10+'HTTP Status:'+res+#13#10+'error code '+IntToStr(GetLastError));
           raise Exception.Create('Unable to download: '+URL+#13#10+'HTTP Status:'+res+#13#10+'error code '+IntToStr(GetLastError));
        end;
      end
      else
      begin
         log_event('error','Unable to download: '+URL+#13#10+'error code '+IntToStr(GetLastError));
         raise Exception.Create('Unable to download: '+URL+#13#10+'error code '+IntToStr(GetLastError));
      end;
    finally
      if Assigned(hFile) then
        InternetCloseHandle(hFile);
    end
    else
    begin
       log_event('error','Unable to download: "'+URL+'" '+GetWinInetError(GetLastError));
       raise Exception.Create('Unable to download: "'+URL+'" '+GetWinInetError(GetLastError));
    end;

  finally
    uri.Free;
    if Assigned(hConnect) then
      InternetCloseHandle(hConnect);
    if Assigned(GlobalhInet) then
      InternetCloseHandle(GlobalhInet);
  end;
end;

function wget(const fileURL, DestFileName: Utf8String; CBReceiver:TObject=Nil):boolean;
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

function GetComputerName : AnsiString;
var
  buffer: array[0..255] of char;
  size: dword;
begin
  size := 256;
  if windows.GetComputerName(buffer, size) then
    Result := buffer
  else
    Result := ''
end;

function getlocal_wapt_version:String;
var
  Registry: TRegistry;
  local_version: string;
  registry_key : String;
begin
  Registry := TRegistry.Create(KEY_READ);
  try
    result :='';
    registry_key := '\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WAPT_is1';
    Registry.RootKey:= HKEY_LOCAL_MACHINE;
    if not Registry.OpenKeyReadOnly(registry_key) then
      registry_key := '\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WAPT_is1';
    if Registry.OpenKeyReadOnly(registry_key) then
      result := Registry.ReadString('DisplayVersion')
    else
      Result := '';
  finally
    Registry.Free;
  end;
end;

function GetDomainName: AnsiString;
var
  hProcess, hAccessToken: THandle;
  InfoBuffer: PChar;
  AccountName: array [0..UNLEN] of Char;
  DomainName: array [0..UNLEN] of Char;

  InfoBufferSize: Cardinal;
  AccountSize: Cardinal;
  DomainSize: Cardinal;
  snu: SID_NAME_USE;
begin
  InfoBufferSize := 1000;
  AccountSize := SizeOf(AccountName);
  DomainSize := SizeOf(DomainName);

  hProcess := GetCurrentProcess;
  Result :='';
  if OpenProcessToken(hProcess, TOKEN_READ, hAccessToken) then
  try
    GetMem(InfoBuffer, InfoBufferSize);
    try
      if GetTokenInformation(hAccessToken, TokenUser, InfoBuffer, InfoBufferSize, InfoBufferSize) then
        LookupAccountSid(nil, PSIDAndAttributes(InfoBuffer)^.sid, AccountName, AccountSize,
                         DomainName, DomainSize, snu)
      else
        RaiseLastOSError;
    finally
      FreeMem(InfoBuffer)
    end;
    Result := DomainName;
  finally
    CloseHandle(hAccessToken);
  end
end;

function GetDNSDomain:AnsiString;
var
  reg:TRegistry;
begin
  reg := TRegistry.create;
  try
    reg.RootKey:=HKEY_LOCAL_MACHINE;
    if reg.OpenKeyReadOnly('SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters') then
    begin
      if reg.ValueExists('Domain') then
        Result := reg.ReadString('Domain');
      if Result='' then
        if reg.ValueExists('DhcpDomain') then
          Result := reg.ReadString('DhcpDomain');
    end;
  finally
    reg.Free;
  end;
end;

function GetUuid:String;
var
  values:String;
  keyvalue: TDynStringArray;
begin
    values := trim(Sto_RedirectedExecute('wmic csproduct get uuid /VALUE'));
    keyvalue := Split(values,'=');
    // got uuid=xxx-sss-fff
    result := Trim(keyvalue[1]);
end;

procedure delete_ini();
begin
     if fileExists('C:\wapt\wapt-get.ini') then
     begin
        DeleteFile('C:\wapt\wapt-get.ini');
        log_event('info','Delete C:\wapt\wapt-get.ini during the installation');
     end;
end;



procedure httpPostData(const UserAgent: string; const url: string; const Data: AnsiString; enableProxy:Boolean= False);
var
  hInet: HINTERNET;
  hHTTP: HINTERNET;
  hReq: HINTERNET;
  uri:TIdURI;
  pdata:String;
const
  wall : WideString = '*/*';
  accept: packed array[0..1] of LPWSTR = (@wall, nil);
  header: string = 'Content-Type: application/json';
begin
  uri := TIdUri.Create(url);
  try
    if enableProxy then
       hInet := InternetOpen(PChar(UserAgent),INTERNET_OPEN_TYPE_PRECONFIG,nil,nil,0)
    else
       hInet := InternetOpen(PChar(UserAgent),INTERNET_OPEN_TYPE_DIRECT,nil,nil,0);
    try
      hHTTP := InternetConnect(hInet, PChar(uri.Host), StrtoInt(uri.Port), PCHAR(uri.Username),PCHAR(uri.Password), INTERNET_SERVICE_HTTP, 0, 1);
      if hHTTP =Nil then
         raise Exception.Create('Unable to connect to '+url);
      try
        hReq := HttpOpenRequest(hHTTP, PChar('POST'), PChar(uri.Document), nil, nil, @accept, 0, 1);
        if hHTTP=Nil then
           raise Exception.Create('Unable to open '+url);
        try
            pdata := Data;
          if not HttpSendRequest(hReq, PChar(header), length(header), PChar(pdata), length(pdata)) then
            raise Exception.Create('HttpOpenRequest failed. ' + SysErrorMessage(GetLastError));
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
    uri.Free;
  end;
end;

function RandomWord(dictSize, lngStepSize, wordLen, minWordLen: Integer): string;
begin
  Result := '';
  if (wordLen < minWordLen) and (minWordLen > 0) then
    wordLen := minWordLen
  else if (wordLen < 1) and (minWordLen < 1) then wordLen := 1;
  repeat
    Result := Result + Chr(Random(dictSize) + lngStepSize);
  until (Length(Result) = wordLen);
end;

{ Twaptautodeploy }

procedure Twaptautodeploy.DoRun;
var
  ErrorMsg: String;
  wapt_version, json_wapt_version,local_waptsetup_dir : String;
  json_send: ISuperObject;
begin
  // quick check parameters
  ErrorMsg := CheckOptions('hds:r:',['help','delete_ini','server:','repourl:']);
  WriteLn(ErrorMsg);
  if ErrorMsg<>'' then begin
   ShowException(Exception.Create(ErrorMsg));
   Terminate;
   Exit;
  end;

  ParseOptions;

  if HasOption('h','help') then
  begin
    WriteHelp;
    Terminate;
    Exit;
  end;

  { add your program here }
  repo_waptsetup := wapt_repo+'/waptagent.exe';
  local_waptsetup_dir := GetTempDir+'\'+(RandomWord(33, 54, Random(12), 2));
  local_waptsetup := local_waptsetup_dir  +'\'+'waptagent.exe';
  json_wapt_version:= httpGetString(wapt_server+'\info');
  wapt_version := SO(json_wapt_version).S['client_version'];
  json_send := TSuperObject.Create;
  json_send.S['uuid']  := uuid;
  json_send.S['wapt_client.last_check_date'] := FormatDateTime('yyyy-mm-dd hh:nn:ss',now);
  if local_wapt_version <> wapt_version then
  try
    json_send.S['wapt_client.status'] := 'UPGRADE-NEEDED';
    httpPostData(ApplicationName,wapt_server+'/update_host',json_send.AsJSon(True));
    CreateDir(local_waptsetup_dir);
    wget(repo_waptsetup,local_waptsetup);
    log_event('info','Launch install of waptagent.exe, current version: '+local_wapt_version+', required version: '+wapt_version);
    try
       if HasOption('d','delete_ini') then
          delete_ini();
       UnitRedirect.Sto_RedirectedExecute(local_waptsetup+' /MERGETASKS=""useWaptServer,autorunTray"" /verysilent');
       log_event('info','WAPT install completed successfully at version '+getlocal_wapt_version);
       json_send.S['wapt_client.error'] := '';
       json_send.S['wapt_client.status'] := 'OK';
       json_send.S['wapt_client.install_date'] := FormatDateTime('yyyy-mm-dd hh:nn:ss',now);
       httpPostData(ApplicationName,wapt_server+'/update_host',json_send.AsJSon(True));
       DeleteFile(PChar(local_waptsetup));
       RemoveDir(local_waptsetup_dir);
    except
      on E : Exception do
      begin
        json_send.S['wapt_client.error'] := E.ClassName+':' + E.Message;
        json_send.S['wapt_client.status'] := 'ERROR';
        json_send.S['wapt_client.install_date'] := FormatDateTime('yyyy-mm-dd hh:nn:ss',now);
        httpPostData(ApplicationName,wapt_server+'/update_host',json_send.AsJSon(True));
        log_event('error','WAPT install failed :  error was '#13#10 + E.ClassName+''#13#10 + E.Message);
      end;
    end;
  except
    on E : Exception do
    begin
        // reset host data on server...
        json_send.S['host.computer_fqdn']  := computer_fqdn;
        json_send.S['host.computer_name']  := computer_name;
        json_send.S['wapt_client.error'] := E.ClassName+':' + E.Message;
        json_send.S['wapt_client.status'] := 'ERROR';
        httpPostData(ApplicationName,wapt_server+'/update_host',json_send.AsJSon(True));
        log_event('error','WAPT check failed :  error was '#13#10 + E.ClassName+''#13#10 + E.Message);
    end;
  end
  else
    log_event('info','Skipped waptagent.exe, current version: '+local_wapt_version+', required version: '+wapt_version);

  // stop program loop
  Terminate;
end;


constructor Twaptautodeploy.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  StopOnException:=True;
  computer_fqdn := LowerCase(GetComputerName)+'.'+GetDNSDomain;
  computer_name := GetComputerName;
  uuid := GetUuid;

  wapt_server := 'http://wapt:8080';
  wapt_repo := 'http://wapt/wapt';
  setup_options := '/MERGETASKS=""useWaptServer,autorunTray"" /verysilent';

  local_wapt_version := getlocal_wapt_version;
end;

destructor Twaptautodeploy.Destroy;
begin
  inherited Destroy;
end;

procedure Twaptautodeploy.ParseOptions;
begin
  // parse parameters
  if HasOption('s','server') then
    wapt_server := GetOptionValue('s','server');

  if HasOption('r','repourl') then
    wapt_repo := GetOptionValue('r','repourl');

  if HasOption('o','options') then
    setup_options := GetOptionValue('o','options');
end;

procedure Twaptautodeploy.WriteHelp;
begin
  { add your help code here }
  writeln('Checks if the current WAPT client is different from wapt server info.');
  writeln('If yes, launch waptclient.exe silently');
  writeln;
  writeln('Usage: ');
  writeln('-h, --help               show this help');
  writeln('-o, --options            innosetup options for waptagent.exe (default: '+setup_options+')');
  writeln('-d, --delete_ini         delete local wapt-get.ini file before the upgrade');
  writeln('-s, --server             waptserver url (default: '+wapt_server+')');
  writeln('-r, --repourl            waptrepo url (default: '+wapt_repo+')');

end;

var
  Application: Twaptautodeploy;

{$R *.res}

begin
  Application:=Twaptautodeploy.Create(nil);
  Application.Title:='WAPTAutoDeploy';
  Application.Run;
  Application.Free;
end.

