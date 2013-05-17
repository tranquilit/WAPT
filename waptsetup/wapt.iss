#define AppName "WAPT"
#define SrcApp AddBackslash(SourcePath) + "..\wapt-get.exe"
#define FileVerStr GetFileVersion(SrcApp)
#define StripBuild(str VerStr) Copy(VerStr, 1, RPos(".", VerStr)-1)
#define AppVerStr StripBuild(FileVerStr)

[Files]
Source: "..\DLLs\*"; DestDir: "{app}\DLLs"; Flags: createallsubdirs recursesubdirs
Source: "..\lib\*"; DestDir: "{app}\lib"; Flags: createallsubdirs recursesubdirs ; Excludes: "*.pyc,test,*.~*" 
Source: "..\libs\*"; DestDir: "{app}\libs"; Flags: createallsubdirs recursesubdirs  ; Excludes: "*.pyc,test,*.~*" 
Source: "..\static\*"; DestDir: "{app}\static"; Flags: createallsubdirs recursesubdirs
Source: "..\templates\*"; DestDir: "{app}\templates"; Flags: createallsubdirs recursesubdirs
Source: "..\ssl\*"; DestDir: "{app}\ssl"; Flags: createallsubdirs recursesubdirs
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
Source: "..\waptservice.exe"; DestDir: "{app}";  BeforeInstall: BeforeWaptServiceInstall('waptservice.exe'); AfterInstall: AfterWaptServiceInstall('waptservice.exe'); Tasks: installService
Source: "..\wapt-get.ini.tmpl"; DestDir: "{app}"; 
Source: "..\wapt-get.py"; DestDir: "{app}"; 
Source: "..\keyfinder.py"; DestDir: "{app}"; 
Source: "..\wapt-get.exe.manifest"; DestDir: "{app}";
Source: "..\wapt-get.exe"; DestDir: "{app}";
Source: "..\dmidecode.exe"; DestDir: "{app}";
Source: "..\wapttray.exe"; DestDir: "{app}"; BeforeInstall: killtask('wapttray.exe'); Tasks: installTray
Source: "..\vc_redist\*"; DestDir: "{tmp}\vc_redist";
Source: "..\lib\site-packages\M2Crypto\libeay32.dll" ; DestDir: "{app}"; 
Source: "..\lib\site-packages\M2Crypto\ssleay32.dll" ; DestDir: "{app}";


[Setup]
AppName={#AppName}
AppVersion={#AppVerStr}
AppVerName={#AppName} {#AppVerStr}
UninstallDisplayName={#AppName} {#AppVerStr}
VersionInfoVersion={#FileVerStr}
VersionInfoTextVersion={#AppVerStr}
AppCopyright=Tranquil IT Systems
DefaultDirName="C:\{#AppName}"
DefaultGroupName={#AppName}
ChangesEnvironment=True
AppPublisher=Tranquil IT Systems
OutputDir="."
OutputBaseFilename=waptsetup
SolidCompression=True
AppPublisherURL=http://www.tranquil.it
AppUpdatesURL=http://wapt.tranquil.it/wapt/waptsetup.exe
AppContact=dev@tranquil.it
AppSupportPhone=+33 2 40 97 57 55
CloseApplications=False
PrivilegesRequired=admin
MinVersion=0,5.0sp4
LicenseFile=..\COPYING.txt
RestartIfNeededByRun=False
SetupIconFile=..\wapt.ico
SignTool=kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}')
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wapt-get.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\wapt-get.exe"; Flags: uninsdeletekey

[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {code:GetRepoURL}
Filename: {app}\wapt-get.ini; Section: global; Key: public_cert; String: {code:GetPublicCert}
Filename: {app}\wapt-get.ini; Section: global; Key: waptupdate_task_period; String: 120; Flags: createkeyifdoesntexist 
Filename: {app}\wapt-get.ini; Section: global; Key: waptupdate_task_maxruntime; String: 30; Flags: createkeyifdoesntexist
Filename: {app}\wapt-get.ini; Section: tranquilit; Key: repo_url; String: http://wapt.tranquil.it/wapt; Tasks: usetispublic; Flags: createkeyifdoesntexist
Filename: {app}\wapt-get.ini; Section: tranquilit; Key: public_cert; String: {app}\ssl\tranquilit.crt; Tasks: usetispublic; Flags: createkeyifdoesntexist
Filename: {app}\wapt-get.ini; Section: global; Key: repositories; String: tranquilit; Flags: createkeyifdoesntexist; Tasks: usetispublic

[Run]
Filename: "msiexec.exe"; Parameters: "/q /i ""{tmp}\vc_redist\vc_red.msi"""; WorkingDir: "{tmp}"; StatusMsg: "Updating MS VC++ libraries for OpenSSL..."; Description: "Update MS VC++ libraries"
Filename: "{app}\wapt-get.exe"; Parameters: "upgradedb"; Flags: runhidden; StatusMsg: "Upgrading local sqlite database structure"; Description: "Upgrade packages list"
Filename: "{app}\wapt-get.exe"; Parameters: "update"; Tasks: updateWapt; Flags: runhidden; StatusMsg: "Updating packages list"; Description: "Update packages list from main repository"
Filename: "{app}\wapt-get.exe"; Parameters: "setup-tasks"; Tasks: setuptasks; Flags: runhidden; StatusMsg: "Setting up daily sheduled tasks"; Description: "Set up daily sheduled tasks"
Filename: "{app}\wapttray.exe"; Tasks: installTray; Flags: runminimized nowait runasoriginaluser postinstall; StatusMsg: "Launch WAPT tray icon"; Description: "Launch WAPT tray icon"

[Icons]
Name: "{commonstartup}\WAPT tray helper"; Tasks: autorunTray; Filename: "{app}\wapttray.exe";

[Tasks]
Name: updateWapt; Description: "Update package list after setup";
Name: installService; Description: "Install WAPT Service";
Name: installTray; Description: "Install WAPT Tray icon";
Name: autorunTray; Description: "Start WAPT Tray icon at logon";
Name: setuptasks; Description: "Creates windows scheduled tasks for update and upgrade";
Name: usetispublic; Description: "Use Tranquil IT public repository as a secondary source";


[UninstallRun]
Filename: "taskkill"; Parameters: "/t /im ""wapttray.exe"" /f"; Flags: runhidden; StatusMsg: "Stopping wapt tray"
Filename: "net"; Parameters: "stop waptservice"; Flags: runhidden; StatusMsg: "Stop swaptservice"
Filename: "{app}\waptservice.exe"; Parameters: "--uninstall"; Flags: runhidden; StatusMsg: "Uninstall swaptservice"

[Code]
#include "services.iss"
var
  rbCustomRepo: TNewRadioButton;
  rbDnsRepo: TNewRadioButton;
  cbSecondRepos : TCheckbox ;
  bIsVerySilent: boolean;
  teWaptUrl,teWaptPublicCert: TEdit;
  lab1:TLabel;
  
procedure InitializeWizard;
var
  CustomPage: TWizardPage;

begin
  CustomPage := CreateCustomPage(wpSelectTasks, 'Installation options', '');

  rbCustomRepo := TNewRadioButton.Create(WizardForm);
  rbCustomRepo.Parent := CustomPage.Surface;
  rbCustomRepo.Checked := True;
  rbCustomRepo.Caption := 'WAPT repository';
  
  teWaptUrl :=TEdit.Create(WizardForm);
  teWaptUrl.Parent := CustomPage.Surface; 
  teWaptUrl.Left :=rbCustomRepo.Left + rbCustomRepo.Width;
  teWaptUrl.Width :=CustomPage.SurfaceWidth - rbCustomRepo.Width;
  

  
  rbDnsRepo := TNewRadioButton.Create(WizardForm);
  rbDnsRepo.Parent := CustomPage.Surface;
  rbDnsRepo.Top := rbCustomRepo.Top + rbCustomRepo.Height + ScaleY(15);
  rbDnsRepo.Width := CustomPage.SurfaceWidth;
  rbDnsRepo.Caption := 'Detect WAPT repository with DNS records';


  lab1 := TLabel.Create(WizardForm);
  lab1.Caption := 'Public certificate for packages validation:';
  lab1.autosize := True;
  lab1.Parent := CustomPage.Surface; 
  lab1.Left := rbDnsRepo.Left;
  lab1.Top := rbDnsRepo.Top + rbDnsRepo.Height + ScaleY(15);

  teWaptPublicCert :=TEdit.Create(WizardForm);
  teWaptPublicCert.Parent := CustomPage.Surface; 
  teWaptPublicCert.Left := lab1.left+lab1.width+5;
  teWaptPublicCert.Top := rbDnsRepo.Top + rbDnsRepo.Height + ScaleY(15);
  teWaptPublicCert.Width := 300;
  
  
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if curPageId=wpSelectTasks then
  begin
    teWaptUrl.Text := GetIniString('Global', 'repo_url', 'http://wapt.tranquil.it/wapt', ExpandConstant('{app}\wapt-get.ini'));
    rbCustomRepo.Checked := teWaptUrl.Text <> ''; 
    rbDnsRepo.Checked := teWaptUrl.Text = ''; 
    teWaptPublicCert.Text := GetIniString('Global', 'public_cert', ExpandConstant('{app}\ssl\tranquilit.crt'), ExpandConstant('{app}\wapt-get.ini'));
  end;
end;

function GetRepoURL(Param: String):String;
begin
  if WizardSilent then
    result := GetIniString('Global', 'repo_url', 'http://wapt.tranquil.it/wapt',ExpandConstant('{app}\wapt-get.ini'))
  else
    if rbCustomRepo.Checked then
       result := teWaptUrl.Text
    else 
       result :='';
end;



function GetPublicCert(Param: String):String;
begin
  if WizardSilent then
    result := GetIniString('Global', 'public_cert', ExpandConstant('{app}\ssl\tranquilit.crt'), ExpandConstant('{app}}\wapt-get.ini'))
  else
    result := teWaptPublicCert.Text;
end;

function InitializeSetup(): Boolean;
begin
  if ServiceExists('waptservice') then
    SimpleStopService('waptservice',True,True);
  Result := True;
end;

procedure DeinitializeSetup();
begin
  if ServiceExists('waptservice') then
    SimpleStartService('waptservice',True,True); 
end;

procedure AfterWaptServiceinstall(exe:String);
var
  ErrorCode: Integer;
begin
//  SimpleCreateService(
//   'waptservice',
//    'waptservice', 
//    ExpandConstant('"{app}\waptservice.exe" --run'),
//    SERVICE_AUTO_START,
//    '','', 
//    False, 
//    False);
  if not ShellExec('', ExpandConstant('{app}\waptservice.exe'),
     '--install', '{app}', SW_HIDE, True, ErrorCode) then
  begin
    RaiseException('Error installing waptservice:'+intToStr(ErrorCode));
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

