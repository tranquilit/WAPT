#define waptsetup 
#define default_repo_url "http://wapt/wapt"
#define default_wapt_server "http://wapt:8080"
#define default_update_period "120"
#define default_update_maxruntime "30"
#define AppName "WAPT"
#include "wapt.iss"

[Files]
; for local waptservice
Source: "..\libzmq.dll"; DestDir: "{app}";
Source: "..\waptservice\win32\*"; DestDir: "{app}\waptservice\win32\";  Flags: createallsubdirs recursesubdirs; Tasks: installService 
Source: "..\waptservice\win64\*"; DestDir: "{app}\waptservice\win64\";  Flags: createallsubdirs recursesubdirs; Tasks: installService
Source: "..\waptservice\waptservice*.py"; DestDir: "{app}\waptservice\"; Tasks: installService
Source: "..\waptservice\network_manager.py"; DestDir: "{app}\waptservice\"; Tasks: installService
Source: "..\waptservice\static\*"; DestDir: "{app}\waptservice\static"; Flags: createallsubdirs recursesubdirs; Tasks: installService 
Source: "..\waptservice\ssl\*"; DestDir: "{app}\waptservice\ssl"; Flags: createallsubdirs recursesubdirs; Tasks: installService 
Source: "..\waptservice\templates\*"; DestDir: "{app}\waptservice\templates"; Flags: createallsubdirs recursesubdirs; Tasks: installService 
; user feedback of waptservice activity
Source: "..\wapttray.exe"; DestDir: "{app}"; BeforeInstall: killtask('wapttray.exe'); 

; sources of installer to rebuild a custom installer
Source: "innosetup\*"; DestDir: "{app}\waptsetup\innosetup";
Source: "wapt.iss"; DestDir: "{app}\waptsetup";
Source: "services.iss"; DestDir: "{app}\waptsetup";
Source: "waptagent.iss"; DestDir: "{app}\waptsetup";
Source: "..\wapt.ico"; DestDir: "{app}";

; global management console
Source: "..\waptconsole.exe.manifest"; DestDir: "{app}";
Source: "..\waptconsole.exe"; DestDir: "{app}";
Source: "..\waptdevutils.py"; DestDir: "{app}";

[Setup]
OutputBaseFilename=waptsetup
DefaultDirName="C:\wapt"

[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: wapt_server; String: {code:GetWaptServerURL};
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {code:GetRepoURL}

[Run]
Filename: "{app}\waptpython.exe"; Parameters: "{app}\waptservice\waptservice.py install"; Flags: runhidden; StatusMsg: "Install waptservice"; Description: "Install waptservice"
Filename: "{app}\wapt-get.exe"; Parameters: "register"; Flags: runhidden postinstall; StatusMsg: "Register computer on the WAPT server"; Description: "Register computer on the WAPT server"
Filename: "{app}\wapttray.exe"; Tasks: autorunTray; Flags: runminimized nowait runasoriginaluser postinstall; StatusMsg: "Launch WAPT tray icon"; Description: "Launch WAPT tray icon"

[Icons]
Name: "{commonstartup}\WAPT tray helper"; Tasks: autorunTray; Filename: "{app}\wapttray.exe"; Flags: excludefromshowinnewinstall;

[Tasks]
Name: autorunTray; Description: "Start WAPT Tray icon at logon"; Flags: unchecked
Name: installService; Description: "Install WAPT Service"; 
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
    result :='http://wapt/wapt' 
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
    result := 'http://wapt:8080'
  if rbDnsServer.Checked then
    begin
      result := '';
    end
    else
      result := teWaptServerUrl.Text;
end;

