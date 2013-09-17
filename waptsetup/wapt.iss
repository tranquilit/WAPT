#define Company "Tranquil IT Systems"
#define SrcApp AddBackslash(SourcePath) + "..\wapt-get.exe"
#define FileVerStr GetFileVersion(SrcApp)
#define StripBuild(str VerStr) Copy(VerStr, 1, RPos(".", VerStr)-1)
#define AppVerStr StripBuild(FileVerStr)
#define default_repo_url "http://wapt.tranquil.it"
#define default_wapt_server "http://wapt:8080"
#define default_update_period "120"
#define default_update_maxruntime "30"

#define output_dir "."

;#define waptserver 
#ifdef waptserver
#define AppName "WAPT Server"
#else
#define AppName "WAPT"
#endif


[Files]
Source: "..\DLLs\*"; DestDir: "{app}\DLLs"; Flags: createallsubdirs recursesubdirs
Source: "..\lib\*"; DestDir: "{app}\lib"; Flags: createallsubdirs recursesubdirs ; Excludes: "*.pyc,test,*.~*" 
Source: "..\libs\*"; DestDir: "{app}\libs"; Flags: createallsubdirs recursesubdirs  ; Excludes: "*.pyc,test,*.~*" 
Source: "..\ssl\*"; DestDir: "{app}\ssl"; Flags: createallsubdirs recursesubdirs
Source: "..\templates\*"; DestDir: "{app}\templates"; Flags: createallsubdirs recursesubdirs
Source: "..\common.py"; DestDir: "{app}"; 
Source: "..\waptpackage.py"; DestDir: "{app}"; 
Source: "..\setuphelpers.py"; DestDir: "{app}"; 
Source: "..\sqlite3.dll"; DestDir: "{app}"; 
Source: "..\Microsoft.VC90.CRT.manifest"; DestDir: "{app}";
Source: "..\msvcm90.dll"; DestDir: "{app}";
Source: "..\msvcp90.dll"; DestDir: "{app}";
Source: "..\msvcr90.dll"; DestDir: "{app}";
Source: "..\python27.dll"; DestDir: "{app}";
Source: "..\pythoncom27.dll"; DestDir: "{app}";
Source: "..\pythoncomloader27.dll"; DestDir: "{app}";
Source: "..\pywintypes27.dll"; DestDir: "{app}";
Source: "..\wapt-get.ini.tmpl"; DestDir: "{app}"; 
Source: "..\wapt-get.py"; DestDir: "{app}"; 
Source: "..\keyfinder.py"; DestDir: "{app}"; 
Source: "..\waptdevutils.py"; DestDir: "{app}"; 
Source: "..\wapt-get.exe.manifest"; DestDir: "{app}";
Source: "..\wapt-get.exe"; DestDir: "{app}";
Source: "..\waptconsole.exe.manifest"; DestDir: "{app}";
Source: "..\waptconsole.exe"; DestDir: "{app}";
Source: "..\waptdevutils.py"; DestDir: "{app}";
Source: "..\dmidecode.exe"; DestDir: "{app}";
Source: "..\wapt.ico"; DestDir: "{app}";
Source: "wapt.iss"; DestDir: "{app}\waptsetup";
Source: "services.iss"; DestDir: "{app}\waptsetup";
Source: "..\COPYING.txt"; DestDir: "{app}";
Source: "..\wapttray.exe"; DestDir: "{app}"; BeforeInstall: killtask('wapttray.exe'); 
Source: "..\vc_redist\*"; DestDir: "{app}\vc_redist";
Source: "..\lib\site-packages\M2Crypto\libeay32.dll" ; DestDir: "{app}"; 
Source: "..\lib\site-packages\M2Crypto\ssleay32.dll" ; DestDir: "{app}";

Source: "..\waptpython.exe"; DestDir: "{app}";
Source: "..\waptservice\waptservice.ini"; DestDir: "{app}\waptservice\";
Source: "..\waptservice\static\*"; DestDir: "{app}\waptservice\static"; Flags: createallsubdirs recursesubdirs
Source: "..\waptservice\templates"; DestDir: "{app}\waptservice\templates"; Flags: createallsubdirs recursesubdirs
Source: "..\waptservice\waptservice*.py"; DestDir: "{app}\waptservice\";  BeforeInstall: BeforeWaptServiceInstall('waptservice.py'); AfterInstall: AfterWaptServiceInstall('waptservice.py'); Tasks: installService
Source: "..\python27.dll"; DestDir: "{sys}"; Flags: sharedfile 32bit;

#ifdef waptserver
Source: "waptserver.iss"; DestDir: "{app}\waptsetup";
Source: "..\waptserver\waptserver.ini.template"; DestDir: "{app}\waptserver"; DestName: "waptserver.ini"
Source: "..\waptserver\*.py"; DestDir: "{app}\waptserver";       
Source: "..\waptserver\*.template"; DestDir: "{app}\waptserver";  
Source: "..\waptserver\templates\*"; DestDir: "{app}\waptserver\templates"; Flags: createallsubdirs recursesubdirs
Source: "..\waptserver\scripts\*"; DestDir: "{app}\waptserver\scripts"; Flags: createallsubdirs recursesubdirs
Source: "..\waptserver\mongodb\mongod.*"; DestDir: "{app}\waptserver\mongodb"; Flags: createallsubdirs recursesubdirs
#endif


[Dirs]
#ifdef waptserver
Name: "{app}\waptserver\repository"
Name: "{app}\waptserver\log"
Name: "{app}\waptserver\repository\wapt"
Name: "{app}\waptserver\repository\wapt-host"
Name: "{app}\waptserver\repository\wapt-group"
Name: "{app}\waptserver\mongodb\data"
Name: "{app}\waptserver\mongodb\log"
#endif

Name: "{app}"; Permissions: everyone-readexec authusers-readexec admins-full  


[Setup]
AppName={#AppName}
AppVersion={#AppVerStr}
AppVerName={#AppName} {#AppVerStr}
UninstallDisplayName={#AppName} {#AppVerStr}
VersionInfoVersion={#FileVerStr}
VersionInfoTextVersion={#AppVerStr}
AppCopyright={#Company}
DefaultDirName="C:\wapt"
DefaultGroupName={#AppName}
ChangesEnvironment=True
AppPublisher={#Company}
OutputDir={#output_dir}
#ifdef waptserver
OutputBaseFilename=waptserversetup
#else
OutputBaseFilename=waptsetup
#endif

SolidCompression=True
AppPublisherURL=http://www.tranquil.it
AppUpdatesURL=http://wapt.tranquil.it/wapt
AppSupportURL=http://dev.tranquil.it/index.php/WAPT_-_apt-get_pour_Windows
AppContact=wapt@lists.tranquil.it
AppSupportPhone=+33 2 40 97 57 55
CloseApplications=False
PrivilegesRequired=admin
MinVersion=0,5.0sp4
LicenseFile=..\COPYING.txt
RestartIfNeededByRun=False
SetupIconFile=..\wapt.ico

;SignTool=kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}')
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wapt-get.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\wapt-get.exe"; Flags: uninsdeletekey

[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {code:GetRepoURL}
Filename: {app}\wapt-get.ini; Section: global; Key: waptupdate_task_period; String: {#default_update_period}; Flags:  createkeyifdoesntexist 
Filename: {app}\wapt-get.ini; Section: global; Key: waptupdate_task_maxruntime; String: {#default_update_maxruntime}; Flags: createkeyifdoesntexist
Filename: {app}\wapt-get.ini; Section: global; Key: wapt_server; String: {code:GetWaptServerURL}; Tasks: useWaptServer; Flags: createkeyifdoesntexist
;Filename: {app}\wapt-get.ini; Section: tranquilit; Key: repo_url; String: http://wapt.tranquil.it/wapt; Tasks: usetispublic; Flags: createkeyifdoesntexist
;Filename: {app}\wapt-get.ini; Section: global; Key: repositories; String: tranquilit; Flags: createkeyifdoesntexist; Tasks: useTISPublic

[Run]
Filename: "{app}\vc_redist\vcredist_x86.exe"; Parameters: "/q"; WorkingDir: "{tmp}"; StatusMsg: "Updating MS VC++ libraries for OpenSSL..."; Description: "Update MS VC++ libraries"
Filename: "{app}\wapt-get.exe"; Parameters: "upgradedb"; Flags: runhidden; StatusMsg: "Upgrading local sqlite database structure"; Description: "Upgrade packages list"
Filename: "{app}\wapt-get.exe"; Parameters: "update"; Flags: runhidden; StatusMsg: "Updating packages list"; Description: "Update packages list from main repository"
Filename: "{app}\wapt-get.exe"; Parameters: "setup-tasks"; Tasks: setuptasks; Flags: runhidden; StatusMsg: "Setting up daily sheduled tasks"; Description: "Set up daily sheduled tasks"
; rights rw for Admins and System, ro for users and authenticated users
Filename: "cmd"; Parameters: "/C echo O| cacls {app} /S:""D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1201a9;;;AU)"""; Flags: runhidden; WorkingDir: "{tmp}"; StatusMsg: "Changing rights on wapt directory..."; Description: "Changing rights on wapt directory"
Filename: "{app}\wapt-get.exe"; Parameters: "register"; Tasks: useWaptServer; Flags: runhidden postinstall; StatusMsg: "Register computer on the WAPT server"; Description: "Register computer on the WAPT server"
Filename: "{app}\wapttray.exe"; Tasks: autorunTray; Flags: runminimized nowait runasoriginaluser postinstall; StatusMsg: "Launch WAPT tray icon"; Description: "Launch WAPT tray icon"

#ifdef waptserver
Filename: "{app}\waptserver\mongodb\mongod.exe"; Parameters: " --config c:\wapt\waptserver\mongodb\mongod.cfg --install";      StatusMsg: "Registering mongodb service..."; Description: "Set up MongoDB Service"
Filename: "{app}\waptpython.exe"; Parameters: "{app}\waptserver\waptserver_servicewrapper.py --startup=auto install"; StatusMsg: "Registering WaptServer Service"    ; Description: "Setup WaptServer Service"
Filename: "net"; Parameters: "start waptmongodb"; StatusMsg: "Starting WaptMongodb service"
Filename: "net"; Parameters: "start waptserver"; StatusMsg: "Starting waptserver service"
Filename: "{app}\wapt-get.exe"; Parameters: "update-packages {app}\waptserver\repository\wapt"; StatusMsg: "Updating server Packages index";
#endif

[Icons]
Name: "{commonstartup}\WAPT tray helper"; Tasks: autorunTray; Filename: "{app}\wapttray.exe"; Flags: excludefromshowinnewinstall;
Name: "{commonstartup}\WAPT session setup"; Tasks: autorunSessionSetup; Filename: "{app}\wapt-get.exe"; Parameters: "session-setup ALL"; Flags: runminimized excludefromshowinnewinstall;

[Tasks]
;Name: updateWapt; Description: "Update package list after setup";
Name: installService; Description: "Install WAPT Service"; 
Name: setupTasks; Description: "Creates windows scheduled tasks for update and upgrade"; 
Name: autorunTray; Description: "Start WAPT Tray icon at logon"; Flags: unchecked
;Name: useTISPublic; Description: "Use Tranquil IT public repository as a secondary source"; Flags: unchecked
#ifdef waptserver
;Name: useWaptServer; Description: "Manage this machine from a central WAPT manage server";
#else
Name: useWaptServer; Description: "Manage this machine from a central WAPT manage server";  Flags: unchecked
#endif
Name: autorunSessionSetup; Description: "Launch WAPT session setup for all packages at logon";

[UninstallRun]
Filename: "taskkill"; Parameters: "/t /im ""waptconsole.exe"" /f"; Flags: runhidden; StatusMsg: "Stopping waptconsole"
Filename: "taskkill"; Parameters: "/t /im ""wapttray.exe"" /f"; Flags: runhidden; StatusMsg: "Stopping wapt tray"
Filename: "net"; Parameters: "stop waptservice"; Flags: runhidden; StatusMsg: "Stop waptservice"
Filename: "{app}\waptservice.exe"; Parameters: "--uninstall"; Flags: runhidden; StatusMsg: "Uninstall waptservice"
#ifdef waptserver
Filename: "net"; Parameters: "stop waptserver"; Flags: runhidden; StatusMsg: "Stop waptserver"
Filename: "{app}\waptpython.exe"; Parameters: "{app}\waptserver\waptserver_servicewrapper.py remove"; StatusMsg: "Unregistering WaptServer Service"
Filename: "net"; Parameters: "stop waptmongod"; Flags: runhidden; StatusMsg: "Stop wapt mongodb"
Filename: "{app}\waptserver\mongodb\mongod.exe"; Parameters: " --config c:\wapt\waptserver\mongodb\mongod.cfg --remove";      StatusMsg: "Unregistering mongodb service..."
#endif

[Code]
#include "services.iss"
var
  rbCustomUrl,rbDnsServer: TNewRadioButton;
  teWaptUrl,teWaptServerUrl: TEdit;
  CustomPage: TWizardPage;

  
procedure InitializeWizard;
begin
  CustomPage := CreateCustomPage(wpSelectTasks, 'Installation options', '');
  
  rbDnsServer := TNewRadioButton.Create(WizardForm);
  rbDnsServer.Parent := CustomPage.Surface;
  rbDnsServer.Checked := True;
  rbDnsServer.Width := CustomPage.SurfaceWidth;
  rbDnsServer.Caption := 'Detect WAPT Server with DNS records';

  rbCustomUrl := TNewRadioButton.Create(WizardForm);
  rbCustomUrl.Parent := CustomPage.Surface; 
  rbCustomUrl.Checked := False;
  rbCustomUrl.Caption := 'WAPT Server';
  rbCustomUrl.Top := rbCustomUrl.Top + rbDnsServer.Height + 3 * ScaleY(15);

  teWaptServerUrl := TEdit.Create(WizardForm);;
  teWaptServerUrl.Parent := CustomPage.Surface; 
  teWaptServerUrl.Left :=rbCustomUrl.Left + rbCustomUrl.Width+5;
  teWaptServerUrl.Width :=CustomPage.SurfaceWidth - rbCustomUrl.Width;
  teWaptServerUrl.Top := teWaptServerUrl.Top + rbDnsServer.Height + 3 * ScaleY(15);
    
end;

procedure CurPageChanged(CurPageID: Integer);
var
  WaptRepo: String;
begin
  if curPageId=customPage.Id then
  begin
    WaptRepo := GetIniString('Global', 'repo_url', '{#default_wapt_server}', ExpandConstant('{app}\wapt-get.ini'));
    if isTaskSelected('useWaptServer') then
      teWaptServerUrl.Text := GetIniString('Global', 'wapt_server', '{#default_wapt_server}', ExpandConstant('{app}\wapt-get.ini'))
    else
      teWaptServerUrl.Text := GetIniString('Global', 'wapt_server', '{#default_repo_url}', ExpandConstant('{app}\wapt-get.ini'));
    rbCustomUrl.Checked := WaptRepo <> '';
    rbDnsServer.Visible := isTaskSelected('useWaptServer');


  end
end;

function GetRepoURL(Param: String):String;
begin
  if WizardSilent then
    result := GetIniString('Global', 'repo_url', '',ExpandConstant('{app}\wapt-get.ini'))
  else
    if rbCustomUrl.Checked then
       result := teWaptServerUrl.Text + '/wapt'
    else 
       result :='';
end;

function GetWaptServerURL(Param: String):String;
begin
  if WizardSilent then
    result := GetIniString('Global', 'wapt_server', '',ExpandConstant('{app}\wapt-get.ini'))
  else
    result := teWaptServerUrl.Text;
end;


function InitializeSetup(): Boolean;
var
  ResultCode: integer;
begin

  // terminate waptconsole
  if Exec('taskkill', '/t /im "waptconsole.exe" /f', '', SW_SHOW,
     ewWaitUntilTerminated, ResultCode) then
  begin
    // handle success if necessary; ResultCode contains the exit code
  end
  else begin
    // handle failure if necessary; ResultCode contains the error code
  end;

  // Proceed Setup

  if ServiceExists('waptservice') then
    SimpleStopService('waptservice',True,True);
  if ServiceExists('waptserver') then
    SimpleStopService('waptserver',True,True);
  if ServiceExists('waptmongodb') then
    SimpleStopService('waptmongodb',True,True);
  

  Result := True;
end;

procedure DeinitializeSetup();
begin
  if ServiceExists('waptservice') then
    SimpleStartService('waptservice',True,True); 
end;

function RunCmd(cmd:String;RaiseOnError:Boolean):String;
var
  ErrorCode: Integer;
  TmpFileName, ExecStdout: string;
begin
  Result := 'Error';
  TmpFileName := ExpandConstant('{tmp}') + '\runresult.txt';
  try
    Exec('cmd','/C '+cmd+'  > "' + TmpFileName + '"', '', SW_HIDE,
      ewWaitUntilTerminated, ErrorCode);
    if RaiseOnError and (ErrorCode>0) then
       RaiseException('La commande '+cmd+' a renvoyé le code d''erreur '+intToStr(ErrorCode));
    if LoadStringFromFile(TmpFileName, ExecStdout) then 
      result := ExecStdOut
    else 
      result:='';
  finally
    if FileExists(TmpFileName) then
	     DeleteFile(TmpFileName);
  end;
end;

procedure AfterWaptServiceinstall(exe:String);
var
  ErrorCode: Integer;
  ExecStdout: string;
  winver: TWindowsVersion ;
begin
//  SimpleCreateService(
//   'waptservice',
//    'waptservice', 
//    ExpandConstant('"{app}\waptservice.exe" --run'),
//    SERVICE_AUTO_START,
//    '','', 
//    False, 
//    False);
  if not Exec(ExpandConstant('{app}\waptpython.exe'),
     ExpandConstant('{app}\waptservice\waptservice_servicewrapper.py --startup=auto install'), 
     '', 
     SW_HIDE, 
     ewWaitUntilTerminated, ErrorCode) then
    RaiseException('Error installing waptservice: '+intToStr(ErrorCode));
   
  GetWindowsVersionEx(winver);
  if winver.Major>=6 then 
  // for win7
  begin  
    ExecStdOut := RunCmd('netsh advfirewall firewall show rule name="waptservice 8088"',False);
    if pos('Ok.',ExecStdOut)<=0 then
      if pos('Ok.',RunCmd('netsh advfirewall firewall add rule name="waptservice 8088" dir=in action=allow protocol=TCP localport=8088',True))<=0 then 
        RaiseException('could not open firewall port 8088 for remote management');
  end
  else
  begin
    ExecStdOut := RunCmd('netsh.exe firewall show portopening',True);
    if pos('waptservice 8088',ExecStdOut)<=0 then
      if pos('Ok.',RunCmd('netsh.exe firewall add portopening name="waptservice 8088" port=8088 protocol=TCP',True))<=0 then
        RaiseException('could not open firewall port 8088 for remote management')
	end;
end;


procedure BeforeWaptServiceinstall(exe:String);
begin
  if ServiceExists('waptservice') then
    SimpleDeleteService('waptservice');
end;

procedure beforeUpdateWapt();
var
  WinHttpReq: Variant;
begin
  try
    WinHttpReq := CreateOleObject('WinHttp.WinHttpRequest.5.1');
    WinHttpReq.Open('GET', teWaptUrl.Text, false);
    WinHttpReq.Send();
  except
    MsgBox('WAPT repository URL is invalid/unreachable.'#13#10' please check repo_url in "wapt-get.ini" file', mbError, MB_OK);
  end;
  if WinHttpReq.Status <> 200 then
    MsgBox('WAPT repository URL is invalid/unreachable.'#13#10' please check repo_url in "wapt-get.ini" file', mbError, MB_OK);
end;

procedure killtask(name:String);
var
  errorcode:integer;
begin
  shellexec('','taskkill','/t /im "'+name+'" /f','',sw_Hide,ewWaitUntilTerminated,Errorcode);
end;

function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  OrigPath := '';
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;

  OrigPath := ';'+OrigPath+';';
  Result := Pos(';' + UpperCase(ExpandConstant(Param)) + ';', UpperCase(OrigPath)) = 0;
  
end;

