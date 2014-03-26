#define waptserver 
#define AppName "WAPT Server"
#define default_repo_url "http://localhost:8080/wapt/"
#define default_wapt_server "http://localhost:8080"
#define default_update_maxruntime "30"
#define default_update_period "120"
#define output_dir "."
#define Company "Tranquil IT Systems"

#include "wapt.iss"


[Files]

Source: "waptserver.iss"; DestDir: "{app}\waptsetup";
Source: "..\waptserver\waptserver.ini.template"; DestDir: "{app}\waptserver"; DestName: "waptserver.ini"
Source: "..\waptserver\*.py"; DestDir: "{app}\waptserver";       
Source: "..\waptserver\*.template"; DestDir: "{app}\waptserver";  
Source: "..\waptserver\templates\*"; DestDir: "{app}\waptserver\templates"; Flags: createallsubdirs recursesubdirs
Source: "..\waptserver\scripts\*"; DestDir: "{app}\waptserver\scripts"; Flags: createallsubdirs recursesubdirs
Source: "..\waptserver\mongodb\mongod.*"; DestDir: "{app}\waptserver\mongodb"; Flags: createallsubdirs recursesubdirs
Source: "..\waptservice\waptservice*.py"; DestDir: "{app}\waptservice\";  BeforeInstall: BeforeWaptServiceInstall('waptservice.py'); AfterInstall: AfterWaptServiceInstall('waptservice.py'); Tasks: installService

[Dirs]
Name: "{app}\waptserver\repository"
Name: "{app}\waptserver\log"
Name: "{app}\waptserver\repository\wapt"
Name: "{app}\waptserver\repository\wapt-host"
Name: "{app}\waptserver\repository\wapt-group"
Name: "{app}\waptserver\mongodb\data"
Name: "{app}\waptserver\mongodb\log"


[Setup]
OutputBaseFilename=waptserversetup
DefaultDirName="C:\wapt"


[RUN]
Filename: "{app}\waptserver\mongodb\mongod.exe"; Parameters: " --config c:\wapt\waptserver\mongodb\mongod.cfg --install";      StatusMsg: "Registering mongodb service..."; Description: "Set up MongoDB Service"
Filename: "{app}\waptpython.exe"; Parameters: "{app}\waptserver\waptserver_servicewrapper.py --startup=auto install"; StatusMsg: "Registering WaptServer Service"    ; Description: "Setup WaptServer Service"
Filename: "net"; Parameters: "start waptmongodb"; StatusMsg: "Starting WaptMongodb service"
Filename: "net"; Parameters: "start waptserver"; StatusMsg: "Starting waptserver service"
Filename: "{app}\wapt-get.exe"; Parameters: "update-packages {app}\waptserver\repository\wapt"; StatusMsg: "Updating server Packages index";
Filename: "{app}\wapt-get.exe"; Parameters: "register"; Flags: runhidden postinstall; StatusMsg: "Register computer on the WAPT server"; Description: "Register computer on the WAPT server"
Filename: "{app}\wapttray.exe"; Tasks: autorunTray; Flags: runminimized nowait runasoriginaluser postinstall; StatusMsg: "Launch WAPT tray icon"; Description: "Launch WAPT tray icon"

[Icons]
Name: "{commonstartup}\WAPT tray helper"; Tasks: autorunTray; Filename: "{app}\wapttray.exe"; Flags: excludefromshowinnewinstall;

[Tasks]
;Name: useWaptServer; Description: "Manage this machine from a central WAPT manage server";
Name: autorunTray; Description: "Start WAPT Tray icon at logon";
Name: installService; Description: "Install WAPT Service"; 

[UninstallRun]
Filename: "net"; Parameters: "stop waptserver"; Flags: runhidden; StatusMsg: "Stop waptserver"
Filename: "{app}\waptpython.exe"; Parameters: "{app}\waptserver\waptserver_servicewrapper.py remove"; StatusMsg: "Unregistering WaptServer Service"
Filename: "net"; Parameters: "stop waptmongod"; Flags: runhidden; StatusMsg: "Stop wapt mongodb"
Filename: "{app}\waptserver\mongodb\mongod.exe"; Parameters: " --config c:\wapt\waptserver\mongodb\mongod.cfg --remove";      StatusMsg: "Unregistering mongodb service..."

[Code]
var
  rbStaticUrl,rbDnsServer: TNewRadioButton;
  CustomPage: TWizardPage;
  teWaptServerUrl:TEdit;
  TLabelRepo,TLabelServer: TLabel;

procedure OnServerClicked(Sender:TObject);
begin
   teWaptServerUrl.Enabled:= not rbDnsServer.Checked;
   teWaptRepoUrl.Enabled:= not rbDnsServer.Checked;
end;


procedure InitializeWizard;
begin
  CustomPage := CreateCustomPage(wpSelectTasks, 'Installation options', '');
  
  TLabelRepo := TLabel.Create(WizardForm);
  TLabelRepo.Parent := CustomPage.Surface; 
  TLabelRepo.Caption := 'Repos URL:';
  
  TLabelServer := TLabel.Create(WizardForm);
  TLabelServer.Parent := CustomPage.Surface; 
  TLabelServer.Caption := 'Server URL:';
  TLabelServer.Top := TLabelServer.Top + TLabelRepo.Height + 2 * ScaleY(15);

  teWaptRepoUrl := TEdit.Create(WizardForm);
  teWaptRepoUrl.Parent := CustomPage.Surface; 
  teWaptRepoUrl.Left :=TLabelRepo.Left + TLabelRepo.Width + 5;
  teWaptRepoUrl.Width :=CustomPage.SurfaceWidth - TLabelRepo.Width;
  

  teWaptServerUrl := TEdit.Create(WizardForm);;
  teWaptServerUrl.Parent := CustomPage.Surface; 
  teWaptServerUrl.Left :=TLabelServer.Left + TLabelServer.Width+5;
  teWaptServerUrl.Width :=CustomPage.SurfaceWidth - TLabelRepo.Width;
  teWaptServerUrl.Top := TLabelServer.Top
end;

procedure CurPageChanged(CurPageID: Integer);
var
  WaptRepo: String;
begin
  if curPageId=customPage.Id then
  begin
    teWaptRepoUrl.Text := GetIniString('Global', 'repo_url', '{#default_repo_url}', ExpandConstant('{app}\wapt-get.ini'));
    teWaptServerUrl.Text := GetIniString('Global', 'wapt_server', '{#default_wapt_server}', ExpandConstant('{app}\wapt-get.ini'));
  end
end;

