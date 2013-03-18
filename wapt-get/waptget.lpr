program waptget;
{ -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
#    WAPT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WAPT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WAPT.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------
}

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Classes, SysUtils, CustApp,
  { you can add units after this }
  Windows, PythonEngine, waptcommon, soutils, tiscommon, FileUtil, NetworkAdapterInfo;
type
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
    Action : String;
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure StopWaptService;
    function SetupWaptService(InstallPath: Utf8String):Boolean;
    procedure Setup(DownloadPath, InstallPath: Utf8String);
    procedure RegisterComputer;
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
    Fwaptdb := TWAPTDB.Create(WaptDBPath);
  end;
  Result := FWaptDB;
end;

procedure pwaptget.DoRun;
var
  DefaultInstallPath,downloadPath: Utf8String;
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
  Action := lowercase(ParamStr(ParamCount));

  // parse parameters
  if HasOption('?') or HasOption('h','--help') then
  begin
    writeln(' -r --repo : URL of dependencies libs (default : '+GetMainWaptRepo+')');
    writeln(' waptupgrade : upgrade wapt-get.exe and database');
    writeln(' waptsetup : install/reinstall dependencies (python libs)');
    writeln(' register : register computer on wapt-server');
  end;

  if HasOption('r','repo') then
    RepoURL := GetOptionValue('r','repo')
  else
    RepoURL := GetMainWaptRepo;

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
    Logger('Current loglevel : '+StrLogLevel[currentLogLevel],DEBUG);
  end;

  if HasOption('v','version') then
    writeln('Win32 Exe wrapper: '+ApplicationName+' '+GetApplicationVersion);
  DefaultInstallPath := TrimFilename('c:\wapt');
  DownloadPath := ExtractFilePath(ParamStr(0));
  // Auto install if wapt-get is not yet in the target directory
  if (action = 'waptsetup') or
    (FileExists(AppendPathDelim(DefaultInstallPath)+'wapt-get.exe') and
        (SortableVersion(GetApplicationVersion) > SortableVersion(GetApplicationVersion(AppendPathDelim(DefaultInstallPath)+'wapt-get.exe')))) or
    (not FileExists(AppendPathDelim(DownloadPath)+'python27.dll')) or
    (not FileExists(AppendPathDelim(DownloadPath)+'wapt-get.exe')) then
  begin
    Writeln('WAPT-GET Setup using repository at '+RepoURL);
    Setup(ParamStr(0),DefaultInstallPath);
    Terminate;
    Exit;
  end
  else
  if (action = 'waptupgrade') then
  begin
    Writeln('WAPT-GET Upgrade using repository at '+RepoURL);
    UpdateCurrentApplication(RepoURL+'/'+ExtractFileName(paramstr(0)),True,' waptsetup');
    Terminate;
    Exit;
  end
  else
  if Action = 'register' then
  begin
    RegisterComputer;
  end
  else
  if Action = 'dumpdb' then
    writeln(WaptDB.dumpdb.AsJson(True))
  else
  if Action = 'upgradedb' then
  begin
    WaptDB.upgradedb;
  end
  else
  begin
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
  {if CheckOpenPort(waptservice_port,'127.0.0.1',1) then
  begin
    ExitStatus := 0;
    Writeln(RunTask('net stop waptservice',ExitStatus));
  end;}
  if (GetServiceStatusByName('','waptservice') = ssRunning) and not StopServiceByName('','waptservice') then
    Raise Exception.create('Unable to stop waptservice');
end;

procedure pwaptget.Setup(DownloadPath,InstallPath:Utf8String);
var
  ZipFilePath,LibsURL:Utf8String;

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
	Writeln('Trying to download '+LibsURL+' to '+ZipFilePath);
	if wget(LibsURL,ZipFilePath) then
  begin
    //release sqlite3.dll for upgrade
    StopWaptService;
    WaptDB := Nil;

	  Writeln('Unzipping '+ZipFilePath);
	  UnzipFile(ZipFilePath,InstallPath);
	  if not SysUtils.DeleteFile(ZipFilePath) then
      logger('  Error : unable to delete temporary zip file, error code : '+intToStr(IOResult),CRITICAL);
  end
  else
    Writeln('Warning : Unable to download '+LibsURL+' to '+ZipFilePath);

  Writeln('Initializing local sqlite DB');
  if FileExists(WaptDB.db.DatabaseName) then
    WaptDB.upgradedb
  else
    WaptDB.OpenDB;

  SetupWaptService(InstallPath);
end;

procedure pwaptget.RegisterComputer;
var
  ws : String;
begin
  writeln(LocalSysinfo.AsJSon(True));
  ws  := GetWaptServerURL;
  if ws<>'' then
  begin
    writeln(' sending computer info to '+ws);
    httpPostData('wapt',ws,'register',LocalSysinfo.AsJSon(True));
  end
  else
    writeln(' no wapt_server defined in inifile '+WaptIniFilename);
end;

function pwaptget.SetupWaptService(InstallPath:Utf8String):boolean;
var
  ExitStatus: Integer;
  SvcStatus :  TServiceState;

begin
  SvcStatus := GetServiceStatusByName('','waptservice');
  If SvcStatus<>ssStopped then
    StopServiceByName('','waptservice');
  if SvcStatus=ssUnknown then
  begin
    Writeln('Install waptservice');
  	Writeln(RunTask(AppendPathDelim(InstallPath)+'waptservice.exe /install',ExitStatus));
  end;
	Writeln('Start waptservice');
  Result := StartServiceByName('','waptservice');
	//Writeln(RunTask('net start waptservice',ExitStatus));
  //ExitStatus = 0;
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

