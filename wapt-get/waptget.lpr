program waptget;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Classes, SysUtils, CustApp,
  { you can add units after this }
  PythonEngine,ShellApi,windows,
  WinInet,zipper,FileUtil,registry;
type
  { waptget }

  pwaptget = class(TCustomApplication)
  protected
    APythonEngine: TPythonEngine;
    procedure DoRun; override;
  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
  end;


  function wget(const fileURL, FileName: String): boolean;
   const
     BufferSize = 1024;
   var
     hSession, hURL: HInternet;
     Buffer: array[1..BufferSize] of Byte;
     BufferLen: DWORD;
     f: File;
     sAppName: string;
     Size: Integer;
   begin
    result := false;
    sAppName := ExtractFileName(ParamStr(0)) ;
    hSession := InternetOpen(PChar(sAppName), INTERNET_OPEN_TYPE_PRECONFIG, nil, nil, 0) ;
    try
      hURL := InternetOpenURL(hSession, PChar(fileURL), nil, 0, 0, 0) ;
      Size:=0;
      try
        AssignFile(f, FileName) ;
        Rewrite(f,1) ;
        repeat
          BufferLen:= 0;
          if InternetReadFile(hURL, @Buffer, SizeOf(Buffer), BufferLen) then
          begin
            inc(Size,BufferLen);
            BlockWrite(f, Buffer, BufferLen)
          end;
        until BufferLen = 0;
        CloseFile(f) ;
        result := (Size>0);
      finally
        InternetCloseHandle(hURL)
      end
    finally
      InternetCloseHandle(hSession)
    end
  end;

Const
  SECURITY_NT_AUTHORITY: TSIDIdentifierAuthority = (Value: (0, 0, 0, 0, 0, 5));
  SECURITY_BUILTIN_DOMAIN_RID = $00000020;
  DOMAIN_ALIAS_RID_ADMINS     = $00000220;
  DOMAIN_ALIAS_RID_USERS      = $00000221;
  DOMAIN_ALIAS_RID_GUESTS     = $00000222;
  DOMAIN_ALIAS_RID_POWER_USERS= $00000223;

function CheckTokenMembership(TokenHandle: THandle; SidToCheck: PSID; var IsMember: BOOL): BOOL; stdcall; external advapi32;

function UserInGroup(Group :DWORD) : Boolean;
var
  pIdentifierAuthority :TSIDIdentifierAuthority;
  pSid : Windows.PSID;
  IsMember    : BOOL;
begin
  pIdentifierAuthority := SECURITY_NT_AUTHORITY;
  Result := AllocateAndInitializeSid(pIdentifierAuthority,2, SECURITY_BUILTIN_DOMAIN_RID, Group, 0, 0, 0, 0, 0, 0, pSid);
  try
    if Result then
      if not CheckTokenMembership(0, pSid, IsMember) then //passing 0 means which the function will be use the token of the calling thread.
         Result:= False
      else
         Result:=IsMember;
  finally
     FreeSid(pSid);
  end;
end;

procedure UnzipFile(ZipFilePath,OutputPath:String);
var
  UnZipper: TUnZipper;
begin
  UnZipper := TUnZipper.Create;
  try
    UnZipper.FileName := ZipFilePath;
    UnZipper.OutputPath := OutputPath;
    UnZipper.Examine;
    UnZipper.UnZipAllFiles;
  finally
    UnZipper.Free;
  end;
end;

procedure AddToUserPath(APath:String);
var
  r:TRegistry;
  SystemPath : String;
begin
  with TRegistry.Create do
  try
    //RootKey:=HKEY_LOCAL_MACHINE;
    OpenKey('Environment',False);
    SystemPath:=ReadString('PATH');
    if pos(LowerCase(APath),LowerCase(SystemPath))=0 then
    begin
      SystemPath:=SystemPath+';'+APath;
      WriteString('PATH',SystemPath);
    end;
  finally
    Free;
  end;

end;

procedure AddToSystemPath(APath:String);
var
  r:TRegistry;
  SystemPath : String;
begin
  with TRegistry.Create do
  try
    RootKey:=HKEY_LOCAL_MACHINE;
    OpenKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment',False);
    SystemPath:=ReadString('PATH');
    if pos(LowerCase(APath),LowerCase(SystemPath))=0 then
    begin
      SystemPath:=SystemPath+';'+APath;
      WriteString('PATH',SystemPath);
    end;
  finally
    Free;
  end;

end;


{ pwaptget }

procedure pwaptget.DoRun;
var
  ErrorMsg,InstallPath,ZipFilePath,LibsURL: String;
  MainModule : TStringList;

  procedure SetFlag( AFlag: PInt; AValue : Boolean );
  begin
    if AValue then
      AFlag^ := 1
    else
      AFlag^ := 0;
  end;

begin
  InstallPath := TrimFilename('c:\wapt');

  // parse parameters
  if HasOption('s','setup') or (not DirectoryExists(InstallPath)) then
  begin
    if not UserInGroup(DOMAIN_ALIAS_RID_ADMINS) then
      raise Exception.Create('You must run this setup with Admin rights');
    ForceDirectory(InstallPath);
    AddToUserPath(InstallPath);
    // Copy wapt-get.exe to install dir
    if CompareFilenamesIgnoreCase(ExtractFilePath(ParamStr(0)), AppendPathDelim(InstallPath))<>0 then
      CopyFile(ParamStr(0),AppendPathDelim(InstallPath)+ExtractFileName(ParamStr(0)),True);
    ZipFilePath := ExtractFilePath(ParamStr(0))+'wapt-libs.zip';

    LibsURL := 'http://wapt/tiswapt/wapt/wapt-libs.zip';
    Writeln('Downloading '+LibsURL+' to '+ZipFilePath);
    if not wget(LibsURL,ZipFilePath) then
    begin
      LibsURL := 'http://srvinstallation.tranquil-it-systems.fr/tiswapt/wapt/wapt-libs.zip';
      Writeln('Downloading '+LibsURL+' to '+ZipFilePath);
      if not wget(LibsURL,ZipFilePath) then
      begin
        Writeln('Unable to download '+LibsURL);
        Terminate;
        Exit;
      end;
    end;
    Writeln('Unzipping '+ZipFilePath);
    UnzipFile(ZipFilePath,InstallPath);
    FileUtil.DeleteFileUTF8(ZipFilePath);
    //Writeln('Installing vcredist_x86.exe');
    //ExecuteProcess(InstallPath+'\redist\vcredist_x86.exe','/qn');
    Terminate;
    Exit;
  end;

  APythonEngine := TPythonEngine.Create(Self);
  with ApythonEngine do
  begin
    DllName := 'python27.dll';
    //APIVersion := 1013;
    RegVersion := '2.7';
    UseLastKnownVersion := False;
    Initialize;
    Py_SetProgramName(PAnsiChar(ParamStr(0)));
    SetFlag(Py_VerboseFlag,     True);
    SetFlag(Py_InteractiveFlag, True);
    SetFlag(Py_NoSiteFlag,      True);
    SetFlag(Py_IgnoreEnvironmentFlag, True);
  end;

  { add your program here }
  try
    MainModule:=TStringList.Create;
    MainModule.LoadFromFile(ExtractFilePath(ParamStr(0))+'wapt-get.py');
    APythonEngine.ExecStrings(MainModule);
  finally
    MainModule.Free;
  end;

  // stop program loop
  Terminate;
end;



constructor pwaptget.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  StopOnException:=True;


end;

destructor pwaptget.Destroy;
begin
  if Assigned(APythonEngine) then
    APythonEngine.Free;
  inherited Destroy;
end;

procedure pwaptget.WriteHelp;
begin
  { add your help code here }
  writeln('Usage: ',ExeName,' -h');
end;

var
  Application: pwaptget;

{$R *.res}

begin
  Application:=pwaptget.Create(nil);
  Application.Title:='wapt-get';
  Application.Run;
  Application.Free;
end.

