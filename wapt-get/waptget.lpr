program waptget;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Classes, SysUtils, CustApp,
  { you can add units after this }
  PythonEngine, waptcommon,FileUtil,IdDNSResolver;
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

{ pwaptget }

procedure pwaptget.DoRun;
var
  InstallPath,ZipFilePath,LibsURL: String;
  MainModule : TStringList;
  downloadPath : String;
  repo,logleveloption : String;
  ExitStatus: Integer;

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
  if HasOption('?') then
  begin
    writeln(' -u --upgrade : upgrade wapt-get.exe');
    writeln(' -s --setup : install/reinstall dependencies (python libs)');
    writeln(' -r --repo : URL of dependencies libs (default : '+FindWaptRepo+')');
  end;

  if HasOption('r','repo') then
    repo := GetOptionValue('r','repo')
  else
    repo := FindWaptRepo;

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
    UpdateCurrentApplication(repo+'/'+ExtractFileName(paramstr(0)),False);


  if HasOption('v','version') then
    writeln('Win32 Exe wrapper: '+ApplicationName+' '+ApplicationVersion);

  // Auto upgrade
  if (FileExists(AppendPathDelim(InstallPath)+'wapt-get.exe') and (ApplicationVersion > ApplicationVersion(AppendPathDelim(InstallPath)+'wapt-get.exe')))
      or HasOption('s','setup') or (not FileExists(AppendPathDelim(InstallPath)+'python27.dll')) then
  begin
    if not UserInGroup(DOMAIN_ALIAS_RID_ADMINS) then
      raise Exception.Create('You must run this setup with Admin rights');
    Logger('Checking install path '+InstallPath,DEBUG);
    ForceDirectory(InstallPath);
    Logger('Adding '+InstallPath+' to system PATH',DEBUG);
    AddToSystemPath(InstallPath);
    // Copy wapt-get.exe to install dir
    downloadPath:=  ParamStrUTF8(0);
    if CompareFilenamesIgnoreCase(ExtractFilePath(downloadPath), AppendPathDelim(InstallPath))<>0 then
    begin
      logger(UTF8ToConsole('Copying '+downloadPath+' to '+AppendPathDelim(InstallPath)+'wapt-get.exe'),INFO);
      if not FileUtil.CopyFile(downloadPath,AppendPathDelim(InstallPath)+'wapt-get.exe',True) then
        logger('  Error : unable to copy, error code : '+intToStr(IOResult),CRITICAL);
    end;
    ZipFilePath := ExtractFilePath(downloadPath)+'wapt-libs.zip';

    LibsURL := repo+'/wapt-libs.zip';
    Writeln(UTF8ToConsole('Downloading '+LibsURL+' to '+ZipFilePath));
    if not wget(LibsURL,ZipFilePath) then
    begin
      Writeln('Unable to download '+LibsURL);
      Terminate;
      Exit;
    end;
    Writeln(RunTask('net stop waptservice',ExitStatus));
    Writeln('Unzipping '+ZipFilePath);
    UnzipFile(ZipFilePath,InstallPath);
    FileUtil.DeleteFileUTF8(ZipFilePath);
    Writeln('Install waptservice');
    try
      Writeln(RunTask(AppendPathDelim(InstallPath)+'waptservice.exe /install',ExitStatus));
    except
      on e:Exception do Writeln('  Error installing service, error code:'+IntToStr(ExitStatus)+', message: '+e.message);
    end;
    Writeln('Start waptservice');
    Writeln(RunTask('net start waptservice',ExitStatus));
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

function GetWaptURL:String;
var
  Resolver:TIdDNSResolver;
begin
  {Resolver := TIdDNSResolver.Create;
  try
    Resolver.QueryResult.Clear;
    Resolver.QueryRecords := [qtService];
    Resolver.Resolve('wapt.'+Resolver.);

  finally
    Resolver.Free;
  end;}

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

