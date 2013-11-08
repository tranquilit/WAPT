program MultiInstall;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Classes, SysUtils,ActiveX,comobj,variants,windows,superobject, CustApp, jwawintype, wininet,
  Process,IdURI,registry,fpjson,jsonparser,eventlog,UnitRedirect ;
  { you can add units after this }

type

  { MultiInstall }

  TMultiInstall = class(TCustomApplication)
  protected
    procedure DoRun; override;
  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
  end;


{ utilities }
function GetWMIObject(const objectName: AnsiString): IDispatch; //create the Wmi instance
var
  chEaten: PULong;
  BindCtx: IBindCtx;
  Moniker: IMoniker;
begin
  OleCheck(CreateBindCtx(0, bindCtx));
  OleCheck(MkParseDisplayName(BindCtx, StringToOleStr(objectName), chEaten, Moniker));
  OleCheck(Moniker.BindToObject(BindCtx, nil, IDispatch, Result));
end;

Function WMIBaseBoardInfo:ISUperObject;
var
  objWMIService : OLEVariant;
  colItems      : OLEVariant;
  colItem       : Variant;
  oEnum         : IEnumvariant;
  iValue        : PULong;
begin;
  result := TSuperObject.Create;
  objWMIService := GetWMIObject('winmgmts:\\localhost\root\CIMV2');
  colItems      := objWMIService.ExecQuery('SELECT * FROM Win32_ComputerSystemProduct','WQL',0);
  oEnum         := IUnknown(colItems._NewEnum) as IEnumVariant;
  while oEnum.Next(1, colItem, iValue) = 0 do
        colItem.;
  begin
  end;
end;

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

procedure launch_install(WaptSetup: UTF8String; OptionInstall: UTF8String);
 var
   AProcess: TProcess;
   AStringList: TStringList;
 begin
   AProcess := TProcess.Create(nil);
   AStringList := TStringList.Create;
   AProcess.CommandLine := Concat(WaptSetup,' ',OptionInstall);
   AProcess.Options := AProcess.Options + [poWaitOnExit, poUsePipes];
   AProcess.Execute;
   AStringList.LoadFromStream(AProcess.Output);
   AStringList.SaveToFile('C:\wapt\waptinstall.txt');
   AStringList.Free;
   AProcess.Free;
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
      begin
        log_event('error','Unable to download: "'+fileURL+'", HTTP Status:'+res);
        raise Exception.Create('Unable to download: "'+fileURL+'", HTTP Status:'+res);
      end
    finally
      InternetCloseHandle(hURL)
    end
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

function is_update(server_version:String):Boolean;
var
  Registry: TRegistry;
  Caption: string;
  registry_key : String;
begin
  {$IFDEF WIN32}registry_key := '\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WAPT_is1';{$ENDIF}
  {$IFDEF WIN64}registry_key := '\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WAPT_is1';{$ENDIF}
  Registry := TRegistry.Create(KEY_READ);
  Registry.RootKey:= HKEY_LOCAL_MACHINE;
  if Registry.OpenKeyReadOnly(registry_key) then
  begin
    Caption := Registry.ReadString('DisplayVersion');
    Registry.Free;
    server_version:= StringReplace(server_version, #9,'',[rfReplaceAll]);
    server_version:= StringReplace(server_version, #32,'',[rfReplaceAll]);
    if Caption = server_version then
    begin
         log_event('info','Wapt have nothing to upgrade');
         Result := False;
    end
    else
    begin
      log_event('warning','Wapt need upgrade');
      Result := True;
    end;
  end
  else
  begin
      log_event('warning','No install of Wapt');
      Result := True;
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

function parse_version(json_string:String):String;
var
  P : TJSONParser;
  D : TJSONData;
  lang : TJSONObject;
begin
  P:= TJSONParser.Create(json_string);
  try
      D := P.Parse;
      lang := TJSONObject(D);
      result := lang.Strings['client_version']
  finally
      lang.Free;
      P.Destroy;
  end;
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


procedure delete_ini();
begin
     if fileExists('C:\wapt\wapt-get.ini') then
     begin
        DeleteFile('C:\wapt\wapt-get.ini');
        log_event('info','Delete C:\wapt\wapt-get.ini during the installation');
     end;
end;



{ MultiInstall }

procedure TMultiInstall.DoRun;
var
  ErrorMsg: String;
  wapt_version, json_wapt_version : String;
  test : String;
  wapt_url :String;
  wapt_server : String;
  repo_waptsetup,wapt_repo,local_waptsetup : String;
begin
  //quick check parameters
  //ErrorMsg:=CheckOptions('r','remove_ini');
  //ErrorMsg:=ErrorMsg + CheckOptions('h','help');
  //WriteLn(ErrorMsg);
  //ReadLn;
  //if ErrorMsg<>'' then begin
   //ShowException(Exception.Create(ErrorMsg));
   //Terminate;
   //Exit;
  //end;

  // parse parameters
  if HasOption('h','help') then begin
    WriteHelp;
    Terminate;
    Exit;
  end;

 if HasOption('s','server') then begin
   wapt_url := GetOptionValue('s','server');
 end
 else
 begin
     wapt_url := 'http://wapt';
 end;
 wapt_server := Concat(wapt_url+':8080');
 wapt_repo := Concat(wapt_url+'/wapt/');
 repo_waptsetup := Concat(wapt_repo+'/waptsetup.exe');
 local_waptsetup := Concat(GetTempDir,'waptsetup.exe');

  { add your program here }
  json_wapt_version := httpGetString(Concat(wapt_server,'/info'));
  wapt_version := parse_version(json_wapt_version);
  //writeln(GetComputerName+'.'+GetDNSDomain);
 // ReadLn;
  if is_update(wapt_version) = True then
  begin
    CoInitialize(nil);
    WriteLn(WMIBaseBoardInfo.AsString);
    //log_event('info','Launch download of waptsetup.exe');
    //wget(repo_waptsetup,local_waptsetup);
    //log_event('info','Launch install of waptsetup.exe');
    try
        if HasOption('r','remove_ini') then begin
           delete_ini();
        end;
       //UnitRedirect.Sto_RedirectedExecute(Concat(local_waptsetup,' ','/MERGETASKS=""useWaptServer,autorunTray"" /verysilent"'));
       log_event('info','The install of Wapt is done');
    except
      on E : Exception do
      begin
          log_event('error','the instll of wapt have failed error was:'#13#10 + E.ClassName+''#13#10 + E.Message);
      end;
    end;

  end;

  // stop program loop
  Terminate;
end;

constructor TMultiInstall.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  StopOnException:=True;
end;

destructor TMultiInstall.Destroy;
begin
  inherited Destroy;
end;

procedure TMultiInstall.WriteHelp;
begin
  { add your help code here }
  writeln('Usage: ');
  writeln('-h, --help               show this help');
  writeln('-r, --remove_ini         remove wapt-get.ini during the upgrade');
  writeln('-s, --server             specify waptserver url ');

end;

var
  Application: TMultiInstall;
begin
  Application:=TMultiInstall.Create(nil);
  Application.Title:='MultiInstall';
  Application.Run;
  Application.Free;
end.

