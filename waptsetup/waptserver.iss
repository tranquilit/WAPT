#define waptserver 
#define AppName "WAPT Server"
#define default_repo_url "http://localhost:8080/wapt/"
#define default_wapt_server "http://localhost:8080"
#define default_update_period "120"
#define output_dir "."
#define Company "Tranquil IT Systems"
#define signtool "kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f"

#include "wapt.iss"


[Files]
; sources of installer to rebuild a custom installer
Source: "innosetup\*"; DestDir: "{app}\waptsetup\innosetup";
Source: "wapt.iss"; DestDir: "{app}\waptsetup";
Source: "waptsetup.iss"; DestDir: "{app}\waptsetup";
Source: "services.iss"; DestDir: "{app}\waptsetup";
Source: "..\wapt.ico"; DestDir: "{app}";

; global management console
Source: "..\waptconsole.exe.manifest"; DestDir: "{app}";
Source: "..\waptconsole.exe"; DestDir: "{app}";
Source: "..\waptdevutils.py"; DestDir: "{app}";

; pymongo
Source: "..\lib\site-packages\pymongo\*"; DestDir: "{app}\lib\site-packages\pymongo"; Flags: createallsubdirs recursesubdirs ; Excludes: "*.pyc,test,*.~*,*.chm,testsuite,Demos,test,HTML"

; Sources for server application
Source: "waptserver.iss"; DestDir: "{app}\waptsetup";
Source: "..\waptserver\waptserver.ini.template"; DestDir: "{app}\waptserver"; DestName: "waptserver.ini"
Source: "..\waptserver\*.py"; DestDir: "{app}\waptserver";       
Source: "..\waptserver\*.template"; DestDir: "{app}\waptserver";  
Source: "..\waptserver\templates\*"; DestDir: "{app}\waptserver\templates"; Flags: createallsubdirs recursesubdirs
Source: "..\waptserver\scripts\*"; DestDir: "{app}\waptserver\scripts"; Flags: createallsubdirs recursesubdirs
Source: "..\waptserver\mongodb\mongod.*"; DestDir: "{app}\waptserver\mongodb"; Flags: createallsubdirs recursesubdirs

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

[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: wapt_server; String: {code:GetWaptServerURL};
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {code:GetRepoURL};
Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: "1";

[RUN]
Filename: "{app}\waptserver\mongodb\mongod.exe"; Parameters: " --config c:\wapt\waptserver\mongodb\mongod.cfg --install"; StatusMsg: "Registering mongodb service..."; Description: "Set up MongoDB Service"
Filename: "{app}\waptpython.exe"; Parameters: """{app}\waptserver\waptserver.py"" install"; StatusMsg: "Registering WaptServer Service"    ; Description: "Setup WaptServer Service"
Filename: "net"; Parameters: "start waptmongodb"; StatusMsg: "Starting WaptMongodb service"
Filename: "net"; Parameters: "start waptserver"; StatusMsg: "Starting waptserver service"
Filename: "{app}\wapt-get.exe"; Parameters: "update-packages ""{app}\waptserver\repository\wapt"""; StatusMsg: "Updating server Packages index";
Filename: "{app}\wapt-get.exe"; Parameters: "register"; Flags: runhidden postinstall; StatusMsg: "Register computer on the WAPT server"; Description: "Register computer on the WAPT server"

[Icons]
Name: "{commonstartup}\WAPT session setup"; Tasks: autorunSessionSetup; Filename: "{app}\wapt-get.exe"; Parameters: "session-setup ALL"; Flags: runminimized excludefromshowinnewinstall;
Name: "{commonstartup}\WAPT tray helper"; Tasks: autorunTray; Filename: "{app}\wapttray.exe"; Flags: excludefromshowinnewinstall;

[Tasks]
Name: autorunSessionSetup; Description: "Lancer WAPT session setup à l'ouverture de session";

[UninstallRun]
Filename: "net"; Parameters: "stop waptserver"; Flags: runhidden; StatusMsg: "Stop waptserver"
Filename: "sc"; Parameters: "delete waptserver"; Flags: runhidden; StatusMsg: "Unregister waptserver"
Filename: "net"; Parameters: "stop waptmongodb"; Flags: runhidden; StatusMsg: "Stop wapt mongodb"
Filename: "sc"; Parameters: "delete waptmongob"; Flags: runhidden; StatusMsg: "Unregister waptmongodb"

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
  
  rbDnsServer := TNewRadioButton.Create(WizardForm);
  rbDnsServer.Parent := CustomPage.Surface;
  rbDnsServer.Checked := False;
  rbDnsServer.Width := CustomPage.SurfaceWidth;
  rbDnsServer.Caption := 'Detect WAPT Info with DNS records';
  rbDnsServer.Onclick := @OnServerClicked;

  rbStaticUrl := TNewRadioButton.Create(WizardForm);
  rbStaticUrl.Parent := CustomPage.Surface; 
  rbStaticUrl.Checked := True;
  rbStaticUrl.Caption := 'Static WAPT Info';
  rbStaticUrl.Top := rbStaticUrl.Top + rbDnsServer.Height + 3 * ScaleY(15);
  rbStaticUrl.Onclick := @OnServerClicked;

  TLabelRepo := TLabel.Create(WizardForm);
  TLabelRepo.Parent := CustomPage.Surface; 
  TLabelRepo.Left := rbStaticUrl.Left + 14;
  TLabelRepo.Caption := 'Repos URL:';
  TLabelRepo.Top := TLabelRepo.Top + rbDnsServer.Height + 5 * ScaleY(15);
  
  TLabelServer := TLabel.Create(WizardForm);
  TLabelServer.Parent := CustomPage.Surface; 
  TLabelServer.Left := rbStaticUrl.Left + 14; 
  TLabelServer.Caption := 'Server URL:';
  TLabelServer.Top := TLabelServer.Top + rbDnsServer.Height + 7 * ScaleY(15);

  teWaptRepoUrl := TEdit.Create(WizardForm);
  teWaptRepoUrl.Parent := CustomPage.Surface; 
  teWaptRepoUrl.Left :=TLabelRepo.Left + TLabelRepo.Width + 5;
  teWaptRepoUrl.Width :=CustomPage.SurfaceWidth - rbStaticUrl.Width;
  teWaptRepoUrl.Top := teWaptRepoUrl.Top + rbDnsServer.Height + 5 * ScaleY(15);

  teWaptServerUrl := TEdit.Create(WizardForm);;
  teWaptServerUrl.Parent := CustomPage.Surface; 
  teWaptServerUrl.Left :=TLabelServer.Left + TLabelServer.Width+5;
  teWaptServerUrl.Width :=CustomPage.SurfaceWidth - rbStaticUrl.Width;
  teWaptServerUrl.Top := teWaptServerUrl.Top + teWaptRepoUrl.Height + 7 * ScaleY(15);   
end;

procedure CurPageChanged(CurPageID: Integer);
var
  WaptRepo: String;
  WaptServer: String;
begin
  if curPageId=customPage.Id then
  begin
    teWaptRepoUrl.Text := GetIniString('Global', 'repo_url', '{#default_repo_url}', ExpandConstant('{app}\wapt-get.ini'));
    teWaptServerUrl.Text := GetIniString('Global', 'wapt_server', '{#default_wapt_server}', ExpandConstant('{app}\wapt-get.ini'));
  end
end;

function GetRepoURL(Param: String):String;
begin
  if WizardSilent then
    result :='{#default_repo_url}' 
  else
    if rbDnsServer.Checked then
    begin
      result := '';
    end
    else
      result := teWaptRepoUrl.Text;
end;

function GetWaptServerURL(Param: String):String;
begin
  if WizardSilent then
    result := '{#default_wapt_server}';
  if rbDnsServer.Checked then
    begin
      result := '';
    end
    else
      result := teWaptServerUrl.Text;
end;