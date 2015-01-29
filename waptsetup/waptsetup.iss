#define waptsetup 
#define default_repo_url ""
#define default_wapt_server ""
#define default_update_period "120"
#define AppName "WAPT"
#define output_dir "."
#define Company "Tranquil IT Systems"
;#define signtool "kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f"

#include "wapt.iss"

[Files]
; sources of installer to rebuild a custom installer (ignoreversion because issc has no version)
Source: "innosetup\*"; DestDir: "{app}\waptsetup\innosetup"; Flags: createallsubdirs recursesubdirs ignoreversion;
Source: "wapt.iss"; DestDir: "{app}\waptsetup";
Source: "waptsetup.iss"; DestDir: "{app}\waptsetup";
Source: "services.iss"; DestDir: "{app}\waptsetup";
Source: "..\wapt.ico"; DestDir: "{app}";

; global management console
Source: "..\waptconsole.exe.manifest"; DestDir: "{app}";
Source: "..\waptconsole.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\waptdevutils.py"; DestDir: "{app}";

[Setup]
OutputBaseFilename=waptsetup
DefaultDirName="C:\wapt"
WizardImageFile=..\tranquilit.bmp

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name:"fr";MessagesFile: "compiler:Languages\French.isl"

[Tasks]
;Name: use_hostpackages; Description: "Use automatic host management based on hostname packages";
Name: autorunSessionSetup; Description: "{cm:StartAfterSetup}";

[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: wapt_server; String: {code:GetWaptServerURL};
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {code:GetRepoURL};
Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: "1";
;Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: "1"; Tasks: use_hostpackages;
;Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: "0"; Tasks: not use_hostpackages;


[Run]
Filename: "{app}\wapt-get.exe"; Parameters: "register"; Flags: runhidden postinstall; StatusMsg: StatusMsg: {cm:RegisterHostOnServer}; Description: "{cm:RegisterHostOnServer}"
Filename: "{app}\wapt-get.exe"; Parameters: "--direct update"; Flags: runhidden; StatusMsg: {cm:UpdateAvailablePkg}; Description: "{cm:UpdateAvailablePkg}"
Filename: "{app}\wapt-get.exe"; Parameters: "add-upgrade-shutdown"; Tasks: autoUpgradePolicy; Flags: runhidden; StatusMsg: {cm:UpdatePkgUponShutdown}; Description: "{cm:UpdatePkgUponShutdown}"

[Icons]
Name: "{commonstartup}\WAPT session setup"; Tasks: autorunSessionSetup; Filename: "{app}\wapt-get.exe"; Parameters: "session-setup ALL"; Flags: runminimized excludefromshowinnewinstall;

[CustomMessages]
;English translations here
en.StartAfterSetup=Launch WAPT setup session upon session opening
en.RegisterHostOnServer=Register this computer onto WAPT server
en.UpdateAvailablePkg=Update the list of packages available on the main repository
en.UpdatePkgUponShutdown=Update packages upon shutdown

;French translations here
fr.StartAfterSetup=Lancer WAPT session setup à l'ouverture de session
fr.RegisterHostOnServer=Enregistre l'ordinateur sur le serveur WAPT
fr.UpdateAvailablePkg=Mise à jour des paquets disponibles sur le dépôt principal
fr.UpdatePkgUponShutdown=Mise à jour des paquets à l'extinction du poste

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

procedure DeinitializeUninstall();
var
    installdir: String;
begin
    installdir := ExpandConstant('{app}');
    if DirExists(installdir) and not runningSilently() and 
       (MsgBox('Des fichiers restent présents dans votre répertoire ' + installdir + ', souhaitez-vous le supprimer ainsi que tous les fichiers qu''il contient ?',
               mbConfirmation, MB_YESNO) = IDYES) then
        Deltree(installdir, True, True, True);
end;
