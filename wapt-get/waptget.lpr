program waptget;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Classes, SysUtils, CustApp,
  { you can add units after this }
  Windows,PythonEngine, waptcommon, JclSysInfo,FileUtil;
type
  { waptget }

  { pwaptget }

  pwaptget = class(TCustomApplication)
  private
    FWaptDB: TWAPTDB;
    function GetWaptDB: TWAPTDB;
    procedure SetWaptDB(AValue: TWAPTDB);
  protected
    APythonEngine: TPythonEngine;
    procedure DoRun; override;
  public
    RepoURL:String;
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure StopWaptService;
    procedure SetupWaptService(InstallPath: Utf8String);
    procedure Setup(DownloadPath, InstallPath: Utf8String);
    procedure InitDB;
    procedure WriteHelp; virtual;
    property WaptDB:TWAPTDB read GetWaptDB write SetWaptDB;
  end;

{ pwaptget }

procedure pwaptget.SetWaptDB(AValue: TWAPTDB);
begin
  if FWaptDB=AValue then Exit;
  if Assigned(FWaptDB) then
    FreeAndNil(FWaptDB);
  FWaptDB:=AValue;
end;

function pwaptget.GetWaptDB: TWAPTDB;
begin
  if not Assigned(FWaptDB) then
  begin
    Fwaptdb := TWAPTDB.Create('c:\wapt\db\wapt.db');
  end;
  Result := FWaptDB;
end;

procedure pwaptget.DoRun;
var
  InstallPath,downloadPath: Utf8String;
  MainModule : TStringList;
  logleveloption : String;

  procedure SetFlag( AFlag: PInt; AValue : Boolean );
  begin
    if AValue then
      AFlag^ := 1
    else
      AFlag^ := 0;
  end;

begin
  InstallPath := TrimFilename('c:\wapt');
  DownloadPath := ParamStr(0);

  // parse parameters
  if HasOption('?') then
  begin
    writeln(' -u --upgrade : upgrade wapt-get.exe');
    writeln(' -s --setup : install/reinstall dependencies (python libs)');
    writeln(' -r --repo : URL of dependencies libs (default : '+FindWaptRepo+')');
  end;

  if HasOption('p','path') then
  begin
    AddToSystemPath(InstallPath);
    Terminate;
  end;

  if HasOption('r','repo') then
    RepoURL := GetOptionValue('r','repo')
  else
    RepoURL := FindWaptRepo;

  if HasOption('l','loglevel') then
  begin
    logleveloption := UpperCase(GetOptionValue('l','loglevel'));
    if logleveloption = 'DEBUG' then
      currentLogLevel := DEBUG
    else if logleveloption = 'INFO' then
      currentLogLevel := INFO
    else if logleveloption = 'WARNING' then
      currentLogLevel := WARNING
    else if logleveloption = 'ERROR' then
      currentLogLevel := ERROR
    else if logleveloption = 'CRITICAL' then
      currentLogLevel := CRITICAL;
  end;

  if HasOption('g','upgrade') then
  begin
    UpdateCurrentApplication(RepoURL+'/'+ExtractFileName(paramstr(0)),False,' --setup');
  end;

  if HasOption('v','version') then
    writeln('Win32 Exe wrapper: '+ApplicationName+' '+ApplicationVersion);

  // Auto upgrade
  if (FileExists(AppendPathDelim(InstallPath)+'wapt-get.exe') and (ApplicationVersion > ApplicationVersion(AppendPathDelim(InstallPath)+'wapt-get.exe')))
      or HasOption('s','setup') or (not FileExists(AppendPathDelim(InstallPath)+'python27.dll')) or (not FileExists(AppendPathDelim(InstallPath)+'wapt-get.exe')) then
  begin
    Setup(downloadPath,InstallPath);
    Terminate;
    Exit;
  end;

  // Running python stuff
  APythonEngine := TPythonEngine.Create(Self);
  with ApythonEngine do
  begin
    DllName := 'python27.dll';
    //APIVersion := 1013;
    RegVersion := '2.7';
    UseLastKnownVersion := False;
    Initialize;
    Py_SetProgramName(PAnsiChar(ParamStr(0)));
    SetFlag(Py_VerboseFlag,     False);
    SetFlag(Py_InteractiveFlag, True);
    SetFlag(Py_NoSiteFlag,      True);
    SetFlag(Py_IgnoreEnvironmentFlag, True);
  end;

  // Load main python application
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
  if assigned(waptdb) then
    waptdb.Free;
  inherited Destroy;
end;

procedure pwaptget.StopWaptService;
var
  ExitStatus : Integer;
begin
  if CheckOpenPort(waptservice_port,'127.0.0.1',1) then
  begin
    ExitStatus := 0;
    Writeln(RunTask('net stop waptservice',ExitStatus));
  end;
end;

procedure pwaptget.Setup(DownloadPath,InstallPath:Utf8String);
var
  ZipFilePath,LibsURL:Utf8String;
  ExitStatus: Integer;

begin
	if not UserInGroup(DOMAIN_ALIAS_RID_ADMINS) then
  	raise Exception.Create('You must run this setup with Admin rights');
	Logger('Checking install path '+InstallPath,DEBUG);
	ForceDirectory(InstallPath);

  Logger('Adding '+InstallPath+' to system PATH',DEBUG);
	AddToSystemPath(InstallPath);

  // Copy wapt-get.exe to install dir if needed
	writeln(DefaultSystemCodePage);
	if CompareFilenamesIgnoreCase(ExtractFilePath(downloadPath), AppendPathDelim(InstallPath))<>0 then
	begin
	  logger('Copying '+downloadPath+' to '+AppendPathDelim(InstallPath)+'wapt-get.exe',INFO);
	  if not Windows.CopyFileW(PWideChar(UTF8Decode(downloadPath)),PWideChar(UTF8Decode(AppendPathDelim(InstallPath)+'wapt-get.exe')),False) then
		  logger('  Error : unable to copy, error code : '+intToStr(IOResult),CRITICAL)
    else
		  logger('  Copy OK',INFO);
	end;

	ZipFilePath := ExtractFilePath(downloadPath)+'wapt-libs.zip';
	LibsURL := RepoURL+'/wapt-libs.zip';
	Writeln('Downloading '+LibsURL+' to '+ZipFilePath);
	if not wget(LibsURL,ZipFilePath) then
	  Raise Exception.Create ('Unable to download '+LibsURL+' to '+ZipFilePath);

  //release sqlite3.dll for upgrade
  StopWaptService;
  WaptDB := Nil;

	Writeln('Unzipping '+ZipFilePath);
	UnzipFile(ZipFilePath,InstallPath);
	if not SysUtils.DeleteFile(ZipFilePath) then
    logger('  Error : unable to delete temporary zip file, error code : '+intToStr(IOResult),CRITICAL);

  Writeln('Initializing local sqlite DB');
  InitDB;

  SetupWaptService(InstallPath);

end;

procedure pwaptget.InitDB;
begin
  WaptDB.CreateTables;
end;

procedure pwaptget.SetupWaptService(InstallPath:Utf8String);
var
  ExitStatus: Integer;

begin
	Writeln('Install waptservice');
	try
	  Writeln(RunTask(AppendPathDelim(InstallPath)+'waptservice.exe /install',ExitStatus));
	except
	  on e:Exception do Writeln('  Error installing service, error code:'+IntToStr(ExitStatus)+', message: '+e.message);
	end;
	Writeln('Start waptservice');
	Writeln(RunTask('net start waptservice',ExitStatus));
end;

procedure pwaptget.WriteHelp;
begin
  { add your help code here }
  writeln('Usage: ',ExeName,' -h');
  writeln('  install on c:\wapt : --setup -s');
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

