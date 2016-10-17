#define waptsetup 
#define default_repo_url ""
#define default_wapt_server ""
#define default_update_period "120"
#define AppName "WAPT"
#define output_dir "."
#define Company "Tranquil IT Systems"
#define install_certs "unchecked"
;#define signtool "kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f"

#include "wapt.iss"

[Files]
; sources of installer to rebuild a custom installer (ignoreversion because issc has no version)
Source: "innosetup\*"; DestDir: "{app}\waptsetup\innosetup"; Flags: createallsubdirs recursesubdirs ignoreversion;
Source: "wapt.iss"; DestDir: "{app}\waptsetup";
Source: "waptsetup.iss"; DestDir: "{app}\waptsetup";
Source: "services.iss"; DestDir: "{app}\waptsetup";
Source: "..\wapt.ico"; DestDir: "{app}";

; sources to regenerate waptupgrade package
Source: "..\waptupgrade\setup.py"; DestDir: "{app}\waptupgrade"; Flags: ignoreversion;
Source: "..\waptupgrade\WAPT\*"; DestDir: "{app}\waptupgrade\WAPT"; Flags: createallsubdirs recursesubdirs ignoreversion;

; global management console
Source: "..\waptconsole.exe.manifest"; DestDir: "{app}";
Source: "..\waptconsole.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\waptdevutils.py"; DestDir: "{app}";


[Setup]
OutputBaseFilename=waptsetup
DefaultDirName=c:\wapt
WizardImageFile=..\tranquilit.bmp

[Languages]
Name:"en"; MessagesFile: "compiler:Default.isl"
Name:"fr";MessagesFile: "compiler:Languages\French.isl"
Name:"de";MessagesFile: "compiler:Languages\German.isl"

[Tasks]
Name: install_certificates; Description: "{cm:InstallSSLCertificates}";  Flags: {#install_certs};
Name: use_waptserver; Description: "{cm:UseWaptServer}"; 
Name: autorunSessionSetup; Description: "{cm:StartAfterSetup}";
Name: verify_server_certificate; Description: "{cm:EnableCheckCertificate}"; Flags: unchecked;


[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: wapt_server; String: {code:GetWaptServerURL}; Tasks: not use_waptserver; AfterInstall: RemoveWaptServer;
Filename: {app}\wapt-get.ini; Section: global; Key: wapt_server; String: {code:GetWaptServerURL}; Tasks: use_waptserver;
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {code:GetRepoURL};
Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: "1"; Tasks: use_waptserver;
Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: "0"; Tasks: not use_waptserver;

[Run]
Filename: "{app}\wapt-get.exe"; Parameters: "--direct enable-check-certificate"; Tasks: verify_server_certificate;  Flags: runhidden postinstall; StatusMsg: StatusMsg: {cm:EnableCheckCertificate}; Description: "{cm:EnableCheckCertificate}"
Filename: "{app}\wapt-get.exe"; Parameters: "--direct register"; Tasks: use_waptserver; Flags: runhidden postinstall; StatusMsg: StatusMsg: {cm:RegisterHostOnServer}; Description: "{cm:RegisterHostOnServer}"
Filename: "{app}\wapt-get.exe"; Parameters: "--direct update"; Flags: runhidden postinstall; StatusMsg: {cm:UpdateAvailablePkg}; Description: "{cm:UpdateAvailablePkg}"
Filename: "{app}\wapt-get.exe"; Parameters: "add-upgrade-shutdown"; Tasks: autoUpgradePolicy; Flags: runhidden; StatusMsg: {cm:UpdatePkgUponShutdown}; Description: "{cm:UpdatePkgUponShutdown}"

[Icons]
Name: "{commonstartup}\WAPT session setup"; Tasks: autorunSessionSetup; Filename: "{app}\wapt-get.exe"; Parameters: "session-setup ALL"; Flags: runminimized excludefromshowinnewinstall;

[CustomMessages]
;English translations here
en.StartAfterSetup=Launch WAPT setup session upon session opening
en.RegisterHostOnServer=Register this computer onto WAPT server
en.UpdateAvailablePkg=Update the list of packages available on the main repository
en.UpdatePkgUponShutdown=Update packages upon shutdown
en.EnableCheckCertificate=Get and enable the check of WaptServer https certificate
en.UseWaptServer=Report computer status to a waptserver and enable remote management
en.InstallSSLCertificates=Install the certificates of authorized packages providers

;French translations here
fr.StartAfterSetup=Lancer WAPT session setup à l'ouverture de session
fr.RegisterHostOnServer=Enregistre l'ordinateur sur le serveur WAPT
fr.UpdateAvailablePkg=Mise à jour des paquets disponibles sur le dépôt principal
fr.UpdatePkgUponShutdown=Mise à jour des paquets à l'extinction du poste
fr.EnableCheckCertificate=Activer la vérification du certificat https du serveur Wapt
fr.UseWaptServer=Activer l'utilisation d'un serveur Wapt et la gestion centralisée de cet ordinateur
fr.InstallSSLCertificates=Installer les certificats des fournisseurs de paquets.

;German translation here
de.StartAfterSetup=WAPT Setup-Sitzung bei Sitzungseröffnung starten
de.RegisterHostOnServer=Diesen Computer auf WAPT Server speichern
de.UpdateAvailablePkg=Liste der verfügbaren Pakete auf Main Repostitory aktualisieren
de.UpdatePkgUponShutdown=Packete aktualisieren beim herunterfahren

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

function GetInitialRepoURL(Param:String):String;
begin
    result := ExpandConstant('{param:repo_url|unknown}');
    if result='unknown' then
    begin
      result := GetIniString('Global', 'repo_url', 'unknown', ExpandConstant('{app}\wapt-get.ini'))
      if result='unknown' then
      begin
        if WizardSilent then
          result := '{#default_repo_url}'
        else
          result := 'unknown';
      end;
    end;
end;

function GetRepoURL(Param:String):String;
begin
  if rbDnsServer.Checked and not rbStaticUrl.Checked then
    result := ''
  else
  if teWaptRepoUrl.Text <> 'unknown' then
    result := teWaptRepoUrl.Text
  else
  begin
    result := ExpandConstant('{param:repo_url|unknown}');
    if result='unknown' then
    begin
      result := GetIniString('Global', 'repo_url', 'unknown', ExpandConstant('{app}\wapt-get.ini'))
      if result='unknown' then
      begin
        if WizardSilent then
          result := '{#default_repo_url}'
        else
          result := 'unknown';
      end;
    end;
  end;
end;

function GetInitialWaptServerURL(Param: String):String;
begin
    result := ExpandConstant('{param:waptserver|unknown}');
    if result='unknown' then
    begin
      result := GetIniString('Global', 'wapt_server', 'unknown', ExpandConstant('{app}\wapt-get.ini'))
      if result='unknown' then
      begin
        if WizardSilent then
          result := '{#default_wapt_server}'
        else
          result := 'unknown';
      end;
    end;
end;


function GetWaptServerURL(Param: String):String;
begin
  if rbDnsServer.Checked and not rbStaticUrl.Checked then
    result := ''
  else
  if teWaptRepoUrl.Text <> 'unknown' then
    result := teWaptServerURL.Text
  else
  begin
    result := ExpandConstant('{param:waptserver|unknown}');
    if result='unknown' then
    begin
      result := GetIniString('Global', 'wapt_server', 'unknown', ExpandConstant('{app}\wapt-get.ini'))
      if result='unknown' then
      begin
        if WizardSilent then
          result := '{#default_wapt_server}'
        else
          result := 'unknown';
      end;
    end;
  end;
end;

procedure RemoveWaptServer();
begin
  DeleteIniEntry('Global','wapt_server',ExpandConstant('{app}\wapt-get.ini'));
end;

procedure InitializeWizard;
begin
  CustomPage := CreateCustomPage(wpSelectTasks, 'Installation options', '');
  
  rbDnsServer := TNewRadioButton.Create(WizardForm);
  rbDnsServer.Parent := CustomPage.Surface;
  rbDnsServer.Width := CustomPage.SurfaceWidth;
  rbDnsServer.Caption := 'Detect WAPT Info with DNS records';
  rbDnsServer.Onclick := @OnServerClicked;

  rbStaticUrl := TNewRadioButton.Create(WizardForm);
  rbStaticUrl.Parent := CustomPage.Surface; 
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
  teWaptRepoUrl.text := 'unknown';

  teWaptServerUrl := TEdit.Create(WizardForm);;
  teWaptServerUrl.Parent := CustomPage.Surface; 
  teWaptServerUrl.Left :=TLabelServer.Left + TLabelServer.Width+5;
  teWaptServerUrl.Width :=CustomPage.SurfaceWidth - rbStaticUrl.Width;
  teWaptServerUrl.Top := teWaptServerUrl.Top + teWaptRepoUrl.Height + 7 * ScaleY(15); 
  teWaptServerUrl.Text := 'unknown';  
end;


procedure DeinitializeUninstall();
var
    installdir: String;
begin
    installdir := ExpandConstant('{app}');
    if DirExists(installdir) and 
      not runningSilently() and  (MsgBox('Des fichiers restent présents dans votre répertoire ' + installdir + ', souhaitez-vous le supprimer ainsi que tous les fichiers qu''il contient ?',
               mbConfirmation, MB_YESNO) = IDYES) then
        Deltree(installdir, True, True, True);
end;

procedure CurPageChanged(CurPageID: Integer);
var
  WaptRepo: String;
  WaptServer: String;
begin
  if curPageId=customPage.Id then
  begin
    teWaptRepoUrl.Text := GetRepoURL('');
    teWaptServerUrl.Text := GetWaptServerURL('');  
    rbDnsServer.Checked := (teWaptRepoUrl.Text='');
    rbStaticUrl.Checked := (teWaptRepoUrl.Text<>'') and (teWaptRepoUrl.Text<>'unknown');

	  teWaptServerUrl.Visible := IsTaskSelected('use_waptserver');
    TLabelServer.Visible := teWaptServerUrl.Visible;
  end
end;


