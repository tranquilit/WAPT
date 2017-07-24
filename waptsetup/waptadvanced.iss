#define waptsetup 
#define default_repo_url ""
#define default_wapt_server ""
#define AppName "WAPT"
#define output_dir "."
#define Company "Tranquil IT Systems"
#define install_certs 
#define send_usage_report 
#define is_waptagent 0 
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

; authorized public keys
Source: "..\ssl\*"; DestDir: "{app}\ssl"; Tasks: installCertificates; Flags: createallsubdirs recursesubdirs

[Setup]
OutputBaseFilename=waptsetupadvanced
DefaultDirName={pf32}\wapt
WizardImageFile=..\tranquilit.bmp
DisableProgramGroupPage=yes

[Languages]
Name:"en"; MessagesFile: "compiler:Default.isl"
Name:"fr";MessagesFile: "compiler:Languages\French.isl"
Name:"de";MessagesFile: "compiler:Languages\German.isl"

[Tasks]
Name: forceUrl; Description: "{cm:ForceUrl}"; GroupDescription: "Base";
Name: installCertificates; Description: "{cm:InstallSSLCertificates}";  GroupDescription: "Base";
Name: autorunSessionSetup; Description: "{cm:StartAfterSetup}"; 
Name: autoUpgradePolicy; Description: "{cm:UpdatePkgUponShutdown}"; Flags: unchecked;
Name: useWaptserver; Description: "{cm:UseWaptServer}"; Flags: unchecked; GroupDescription: "Central management";
Name: useHostPackages; Description: "{cm:UseHostPackages}"; Flags: unchecked; GroupDescription: "Central management"; 
Name: useKerberos; Description: "{cm:UseKerberos}"; Flags: unchecked; GroupDescription: "Security";
Name: verifyCert; Description: "{cm:VerifyCert}"; Flags: unchecked; GroupDescription: "Security";
Name: checkCertificateValidity; Description: "{cm:checkCertificateValidity}"; Flags: unchecked; GroupDescription: "Security";


[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: wapt_server; String: {code:GetWaptServerURL}; Tasks: not useWaptserver; AfterInstall: RemoveWaptServer;
Filename: {app}\wapt-get.ini; Section: global; Key: wapt_server; String: {code:GetWaptServerURL}; Tasks: useWaptserver;
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {code:GetRepoURL};
Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: "1"; Tasks: useHostPackages; 
Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: "0"; Tasks: not useHostPackages;
Filename: {app}\wapt-get.ini; Section: global; Key: send_usage_report; String:  {#send_usage_report}; 
Filename: {app}\wapt-get.ini; Section: global; Key: use_kerberos; String: "0"; Tasks: not useKerberos;
Filename: {app}\wapt-get.ini; Section: global; Key: use_kerberos; String: "1"; Tasks: useKerberos;
Filename: {app}\wapt-get.ini; Section: global; Key: verify_cert; String: "0"; Tasks: not verifyCert;
Filename: {app}\wapt-get.ini; Section: global; Key: verify_cert; String: "1"; Tasks: verifyCert;
Filename: {app}\wapt-get.ini; Section: global; Key: check_certificate_validity; String: "0"; Tasks: not checkCertificateValidity;
Filename: {app}\wapt-get.ini; Section: global; Key: check_certificate_validity; String: "1"; Tasks: checkCertificateValidity;


[Run]
Filename: "{app}\wapt-get.exe"; Parameters: "add-upgrade-shutdown"; Flags: runhidden; Tasks: autoUpgradePolicy; StatusMsg: {cm:UpdatePkgUponShutdown}; Description: "{cm:UpdatePkgUponShutdown}"
Filename: "{app}\wapt-get.exe"; Parameters: "remove-upgrade-shutdown"; Flags: runhidden; Tasks: not autoUpgradePolicy; StatusMsg: {cm:UpdatePkgUponShutdown}; Description: "{cm:UpdatePkgUponShutdown}"
;Filename: "{app}\wapt-get.exe"; Parameters: "--direct enable-check-certificate"; Tasks: verifyCert useWaptserver;  Flags: runhidden; StatusMsg: StatusMsg: {cm:EnableCheckCertificate}; Description: "{cm:EnableCheckCertificate}"
Filename: "{app}\wapt-get.exe"; Parameters: "--direct register"; Tasks: useWaptserver; Flags: runasoriginaluser runhidden; StatusMsg: StatusMsg: {cm:RegisterHostOnServer}; Description: "{cm:RegisterHostOnServer}"
Filename: "{app}\wapt-get.exe"; Parameters: "--direct update"; Flags: runasoriginaluser runhidden; StatusMsg: {cm:UpdateAvailablePkg}; Description: "{cm:UpdateAvailablePkg}"

Filename: "{app}\wapttray.exe"; Tasks: autorunTray; Flags: runminimized nowait runasoriginaluser skipifsilent postinstall; StatusMsg: "Lancement de l'icône de notification"; Description: "Lancement de l'icône de notification"

[Icons]
Name: "{commonstartup}\WAPT session setup"; Filename: "{app}\wapt-get.exe"; Parameters: "session-setup ALL"; Flags: runminimized excludefromshowinnewinstall; Tasks: autorunSessionSetup;
Name: "{group}\Console WAPT"; Filename: "{app}\waptconsole.exe"; WorkingDir: "{app}" ; Check: IsWaptAgentCheck;

[CustomMessages]
;English translations here
en.StartAfterSetup=Launch WAPT setup session upon session opening
en.RegisterHostOnServer=Register this computer onto WAPT server
en.UpdateAvailablePkg=Update the list of packages available on the main repository
en.UpdatePkgUponShutdown=Update packages upon shutdown
en.EnableCheckCertificate=Get and enable the check of WaptServer https certificate
en.UseWaptServer=Report computer status to a waptserver and enable remote management
en.InstallSSLCertificates=Install the certificates provided by this installer
en.UseKerberos=Use kerberos to authenticate the register
en.VerifyCert=Verify https certificates
en.ForceUrl=Update Main Repository and WaptServer URL even if already set.
en.checkCertificateValidity=Check package certificate validity
en.UseHostPackages=Use host packages

;French translations here
fr.StartAfterSetup=Lancer WAPT session setup à l'ouverture de session
fr.RegisterHostOnServer=Enregistre l'ordinateur sur le serveur WAPT
fr.UpdateAvailablePkg=Mise à jour des paquets disponibles sur le dépôt principal
fr.UpdatePkgUponShutdown=Mise à jour des paquets à l'extinction du poste
fr.EnableCheckCertificate=Activer la vérification du certificat https du serveur Wapt
fr.UseWaptServer=Activer l'utilisation d'un serveur Wapt et la gestion centralisée de cet ordinateur
fr.InstallSSLCertificates=Installer les certificats fournis par cet installeur.
fr.UseKerberos=Utiliser le compte Kerberos pour authentifier le register.
fr.VerifyCert=Vérifier les certificats https
fr.ForceUrl=Met à jour les URL du dépot principal et du serveur.
fr.checkCertificateValidity=Vérifier la validité des certificat des paquets
fr.UseHostPackages=Utiliser les paquets machine


;German translation here
de.StartAfterSetup=WAPT Setup-Sitzung bei Sitzungseröffnung starten
de.RegisterHostOnServer=Diesen Computer auf WAPT Server speichern
de.UpdateAvailablePkg=Liste der verfügbaren Pakete auf Main Repostitory aktualisieren
de.UpdatePkgUponShutdown=Packete aktualisieren beim herunterfahren

[Code]
var
  cbStaticUrl,cbDnsServer: TNewRadioButton;
  CustomPage: TWizardPage;
  edWaptServerUrl,edDNSDomain:TEdit;
  labRepo,labServer,labDNSDomain: TLabel;

procedure OnServerClicked(Sender:TObject);
begin
   edWaptServerUrl.Enabled:= not cbDnsServer.Checked;
   edWaptRepoUrl.Enabled:= not cbDnsServer.Checked;
   edDNSDomain.Enabled := cbDnsServer.Checked;
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
      result := GetIniString('Global', 'repo_url','{#default_repo_url}', ExpandConstant('{app}\wapt-get.ini'))
  end;
end;

function GetWaptServerURL(Param: String):String;
begin
  if rbDnsServer.Checked and not rbStaticUrl.Checked then
    result := ''
  else
  if teWaptServerURL.Text <> 'unknown' then
    result := teWaptServerURL.Text
  else
  begin
    result := ExpandConstant('{param:wapt_server|unknown}');
    if result='unknown' then
      result := GetIniString('Global', 'wapt_server','{#default_wapt_server}', ExpandConstant('{app}\wapt-get.ini'));
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
  
  teWaptRepoUrl := TEdit.Create(WizardForm);
  teWaptRepoUrl.Parent := CustomPage.Surface; 
  teWaptRepoUrl.Left :=TLabelRepo.Left + TLabelRepo.Width + 5;
  teWaptRepoUrl.Width :=CustomPage.SurfaceWidth - rbStaticUrl.Width;
  teWaptRepoUrl.Top := teWaptRepoUrl.Top + rbDnsServer.Height + 5 * ScaleY(15);
  teWaptRepoUrl.text := 'unknown';

  TLabelRepo := TLabel.Create(WizardForm);
  TLabelRepo.Parent := CustomPage.Surface; 
  TLabelRepo.Left := teWaptRepoUrl.Left + 5;
  TLabelRepo.Caption := 'example: http://srvwapt.domain.lan/wapt';
  TLabelRepo.Top := teWaptRepoUrl.Top + teWaptRepoUrl.Height + ScaleY(2);


  labServer := TLabel.Create(WizardForm);
  labServer.Parent := CustomPage.Surface; 
  labServer.Left := rbStaticUrl.Left + 14; 
  labServer.Caption := 'Server URL:';
  labServer.Top := rbDnsServer.Height + 9 * ScaleY(15);

  teWaptServerUrl := TEdit.Create(WizardForm);;
  teWaptServerUrl.Parent := CustomPage.Surface; 
  teWaptServerUrl.Left :=labServer.Left + labServer.Width+5;
  teWaptServerUrl.Width :=CustomPage.SurfaceWidth - rbStaticUrl.Width;
  teWaptServerUrl.Top := teWaptServerUrl.Top + teWaptRepoUrl.Height + 9 * ScaleY(15); 
  teWaptServerUrl.Text := 'unknown';  

  labHintServer := TLabel.Create(WizardForm);
  labHintServer.Parent := CustomPage.Surface; 
  labHintServer.Left := teWaptServerUrl.Left + 5; 
  labHintServer.Caption := 'example: https://srvwapt.domain.lan';
  labHintServer.Top := teWaptServerUrl.Top + teWaptServerUrl.Height + ScaleY(2);


end;


procedure DeinitializeUninstall();
var
    installdir: String;
begin
    installdir := ExpandConstant('{app}');
    if DirExists(installdir) then
    begin
      if (not runningSilently() and  (MsgBox('Des fichiers restent présents dans votre répertoire ' + installdir + ', souhaitez-vous le supprimer ainsi que tous les fichiers qu''il contient ?',
               mbConfirmation, MB_YESNO) = IDYES))
               
         or (ExpandConstant('{param:purge_wapt_dir|0}')='1') then
        Deltree(installdir, True, True, True);
    End;
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
    teWaptServerUrl.Visible := IsTaskSelected('useWaptserver');
	  labHintServer.Visible := IsTaskSelected('useWaptserver');
	  labServer.Visible := IsTaskSelected('useWaptserver');

    rbDnsServer.Checked := (teWaptRepoUrl.Text='');
    rbStaticUrl.Checked := (teWaptRepoUrl.Text<>'') and (teWaptRepoUrl.Text<>'unknown');
    
  end
end;

function IsWaptAgentCheck:Boolean;
begin
	Result := {#is_waptagent} <> 0;
end;

