program waptget;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Classes, SysUtils, CustApp,
  { you can add units after this }
  PythonEngine,ShellApi,windows,
  WinInet,zipper;
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


  function GetInetFile (const fileURL, FileName: String): boolean;
   const
     BufferSize = 1024;
   var
     hSession, hURL: HInternet;
     Buffer: array[1..BufferSize] of Byte;
     BufferLen: DWORD;
     f: File;
     sAppName: string;
   begin
    result := false;
    sAppName := ExtractFileName(ParamStr(0)) ;
    hSession := InternetOpen(PChar(sAppName), INTERNET_OPEN_TYPE_PRECONFIG, nil, nil, 0) ;
    try
     hURL := InternetOpenURL(hSession, PChar(fileURL), nil, 0, 0, 0) ;
     try
      AssignFile(f, FileName) ;
      Rewrite(f,1) ;
      repeat
       InternetReadFile(hURL, @Buffer, SizeOf(Buffer), BufferLen) ;
       BlockWrite(f, Buffer, BufferLen)
      until BufferLen = 0;
      CloseFile(f) ;
      result := True;
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

function  UserInGroup(Group :DWORD) : Boolean;
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

{ pwaptget }

procedure pwaptget.DoRun;
var
  ErrorMsg,ZipFilePath: String;
  MainModule : TStringList;
  UnZipper: TUnZipper;

begin
  // parse parameters
  if HasOption('s','setup') or (not DirectoryExists('c:\wapt')) then begin
    if not UserInGroup(DOMAIN_ALIAS_RID_ADMINS) then
      raise Exception.Create('You must run this setup with Admin rights');
    if not DirectoryExists('c:\wapt') then
      mkdir('c:\wapt');
    if LowerCase(ExtractFilePath(ParamStr(0)))<>'c:\wapt' then
      CopyFile(PChar(ParamStr(0)),PChar('c:\wapt\'+ExtractFileName(ParamStr(0))),False);
    ZipFilePath := ExtractFilePath(ParamStr(0))+'wapt-libs.zip';
    Writeln('Downloading '+'http://wapt/tiswapt/wapt/wapt-libs.zip'+' to '+ExtractFilePath(ParamStr(0))+'wapt-libs.zip');
    GetInetFile('http://wapt/tiswapt/wapt/wapt-libs.zip',ExtractFilePath(ParamStr(0))+'wapt-libs.zip');
    Writeln('Unzipping '+ZipFilePath);
    UnZipper := TUnZipper.Create;
    try
      UnZipper.FileName := ZipFilePath;
      UnZipper.OutputPath := 'c:\wapt';
      UnZipper.Examine;
      UnZipper.UnZipAllFiles;
    finally
      UnZipper.Free;
    end;
    Writeln();
    Writeln('Installing vcredist_x86.exe');
    ExecuteProcess(ExtractFilePath(ParamStr(0))+'redist\vcredist_x86.exe','/qn');
    Terminate;
    Exit;
  end;

  APythonEngine := TPythonEngine.Create(Self);
  with ApythonEngine do
  begin
    DllName := 'python27.dll';
    APIVersion := 1013;
    RegVersion := '2.7';
    UseLastKnownVersion := False;
    PyFlags := [pfIgnoreEnvironmentFlag];
    RedirectIO := False;
    UseWindowsConsole := False  ;
  end;
  APythonEngine.Initialize;
  APythonEngine.Py_SetProgramName(PAnsiChar(ParamStr(0)));

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
  Application.Run;
  Application.Free;
end.

