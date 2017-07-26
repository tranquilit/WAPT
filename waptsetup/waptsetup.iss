#define waptsetup 
#define default_repo_url ""
#define default_wapt_server ""
#define repo_url ""
#define wapt_server ""
#define AppName "WAPT"
#define output_dir "."
#define Company "Tranquil IT Systems"
#define install_certs 0
#define send_usage_report 0
#define is_waptagent 0
#define use_kerberos 1
#define check_certificates_validity 1
#define verify_cert 1
#define default_dnsdomain ""

;#define signtool "kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f"

; for fast compile in developent mode
;#define FastDebug

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
Source: "..\ssl\*"; DestDir: "{app}\ssl"; Flags: createallsubdirs recursesubdirs; Check: InstallCertCheck();
;Source: "..\ssl\*"; DestDir: "{app}\ssl"; Tasks: installCertificates; Flags: createallsubdirs recursesubdirs

[Setup]
OutputBaseFilename=waptsetup
DefaultDirName={pf32}\wapt
WizardImageFile=..\tranquilit.bmp
DisableProgramGroupPage=yes

[Languages]
Name:"en"; MessagesFile: "compiler:Default.isl"
Name:"fr";MessagesFile: "compiler:Languages\French.isl"
Name:"de";MessagesFile: "compiler:Languages\German.isl"

[Tasks]
;Name: installCertificates; Description: "{cm:InstallSSLCertificates}";  GroupDescription: "Base";

[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: wapt_server; String: {code:GetWaptServerURL}; 
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {code:GetRepoURL};
Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: "1"; 
Filename: {app}\wapt-get.ini; Section: global; Key: send_usage_report; String:  {#send_usage_report}; 
Filename: {app}\wapt-get.ini; Section: global; Key: use_kerberos; String:  {#use_kerberos}; 
Filename: {app}\wapt-get.ini; Section: global; Key: check_certificates_validity; String:  {#check_certificates_validity};
; needs to be relocated if waptagent is compiled on another base directory than target computers 
Filename: {app}\wapt-get.ini; Section: global; Key: verify_cert; String: {code:RelocateCertDirWaptBase}; 
Filename: {app}\wapt-get.ini; Section: global; Key: dnsdomain; String: {code:GetDNSDomain}; 


[Run]
Filename: "{app}\wapt-get.exe"; Parameters: "--direct register"; Flags: runasoriginaluser runhidden postinstall; StatusMsg: StatusMsg: {cm:RegisterHostOnServer}; Description: "{cm:RegisterHostOnServer}"
Filename: "{app}\wapt-get.exe"; Parameters: "--direct --force update"; Flags: runasoriginaluser runhidden postinstall; StatusMsg: {cm:UpdateAvailablePkg}; Description: "{cm:UpdateAvailablePkg}"
Filename: "{app}\wapt-get.exe"; Parameters: "add-upgrade-shutdown"; Flags: runhidden; StatusMsg: {cm:UpdatePkgUponShutdown}; Description: "{cm:UpdatePkgUponShutdown}"

[Icons]
Name: "{commonstartup}\WAPT session setup"; Filename: "{app}\wapt-get.exe"; Parameters: "session-setup ALL"; Flags: runminimized excludefromshowinnewinstall;
Name: "{group}\Console WAPT"; Filename: "{app}\waptconsole.exe"; WorkingDir: "{app}" ; Check: Not IsWaptAgent();

[CustomMessages]
;English translations here
en.StartAfterSetup=Launch WAPT setup session upon session opening
en.RegisterHostOnServer=Register this computer onto WAPT server
en.UpdateAvailablePkg=Update the list of packages available on the main repository
en.UpdatePkgUponShutdown=Update packages upon shutdown
en.EnableCheckCertificate=Get and enable the check of WaptServer https certificate
en.UseWaptServer=Report computer status to a waptserver and enable remote management
en.InstallSSLCertificates=Install the certificates provided by this installer

;French translations here
fr.StartAfterSetup=Lancer WAPT session setup à l'ouverture de session
fr.RegisterHostOnServer=Enregistre l'ordinateur sur le serveur WAPT
fr.UpdateAvailablePkg=Mise à jour des paquets disponibles sur le dépôt principal
fr.UpdatePkgUponShutdown=Mise à jour des paquets à l'extinction du poste
fr.EnableCheckCertificate=Activer la vérification du certificat https du serveur Wapt
fr.UseWaptServer=Activer l'utilisation d'un serveur Wapt et la gestion centralisée de cet ordinateur
fr.InstallSSLCertificates=Installer les certificats fournis par cet installeur.

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
  if cbDnsServer.Checked and not cbStaticUrl.Checked then
    result := ''
  else
  if edWaptRepoUrl.Text <> 'unknown' then
    result := edWaptRepoUrl.Text
  else
  begin
    result := ExpandConstant('{param:repo_url|unknown}');
    if result='unknown' then
	begin
	  result := '{#repo_url}';
	  if result = '' then
		result := GetIniString('Global', 'repo_url','{#default_repo_url}', ExpandConstant('{app}\wapt-get.ini'))
    end;
  end;
end;

function GetWaptServerURL(Param: String):String;
begin
  if cbDnsServer.Checked and not cbStaticUrl.Checked then
    result := ''
  else
  if edWaptServerUrl.Text <> 'unknown' then
    result := edWaptServerUrl.Text
  else
  begin
    result := ExpandConstant('{param:wapt_server|unknown}');
    if result='unknown' then
	begin
	  result := '{#wapt_server}';
	  if result = '' then
          result := GetIniString('Global', 'wapt_server','{#default_wapt_server}', ExpandConstant('{app}\wapt-get.ini'));
	end;
  end;
end;

function GetDNSDomain(Param: String):String;
begin
  if not cbDnsServer.Checked and not cbStaticUrl.Checked then
    result := ''
  else
  if edDNSDomain.Text <> 'unknown' then
    result := edDNSDomain.Text
  else
  begin
    result := ExpandConstant('{param:dnsdomain|unknown}');
    if result='unknown' then
	begin
	  result := '{#default_dnsdomain}';
	  if result = '' then
		result := GetIniString('Global', 'dnsdomain','{#default_dnsdomain}', ExpandConstant('{app}\wapt-get.ini'))
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
  
  cbDnsServer := TNewRadioButton.Create(WizardForm);
  cbDnsServer.Parent := CustomPage.Surface;
  cbDnsServer.Width := CustomPage.SurfaceWidth;
  cbDnsServer.Caption := 'Detect WAPT Info with DNS records';
  cbDnsServer.Onclick := @OnServerClicked;

  labDNSDomain := TLabel.Create(WizardForm);
  labDNSDomain.Parent := CustomPage.Surface; 
  labDNSDomain.Left := cbDnsServer.Left + 14;
  labDNSDomain.Caption := 'DNS Domain to lookup:';
  labDNSDomain.Top := cbDnsServer.Top + cbDnsServer.Height + 5;

  edDNSDomain := TEdit.Create(WizardForm);
  edDNSDomain.Parent := CustomPage.Surface; 
  edDNSDomain.Left := labDNSDomain.Left + labDNSDomain.Width + 5;
  edDNSDomain.Width := CustomPage.SurfaceWidth - labDNSDomain.Width;
  edDNSDomain.Top := labDNSDomain.Top;
  edDNSDomain.text := 'unknown';
  
  cbStaticUrl := TNewRadioButton.Create(WizardForm);
  cbStaticUrl.Parent := CustomPage.Surface; 
  cbStaticUrl.Caption := 'Static WAPT Info';
  cbStaticUrl.Top := cbStaticUrl.Top + cbDnsServer.Height + 3 * ScaleY(15);
  cbStaticUrl.Onclick := @OnServerClicked;

  labRepo := TLabel.Create(WizardForm);
  labRepo.Parent := CustomPage.Surface; 
  labRepo.Left := cbStaticUrl.Left + 14;
  labRepo.Caption := 'Repos URL:';
  labRepo.Top := labRepo.Top + cbDnsServer.Height + 5 * ScaleY(15);
  
  labServer := TLabel.Create(WizardForm);
  labServer.Parent := CustomPage.Surface; 
  labServer.Left := cbStaticUrl.Left + 14; 
  labServer.Caption := 'Server URL:';
  labServer.Top := labServer.Top + cbDnsServer.Height + 9 * ScaleY(15);

  edWaptRepoUrl := TEdit.Create(WizardForm);
  edWaptRepoUrl.Parent := CustomPage.Surface; 
  edWaptRepoUrl.Left :=labRepo.Left + labRepo.Width + 5;
  edWaptRepoUrl.Width :=CustomPage.SurfaceWidth - cbStaticUrl.Width;
  edWaptRepoUrl.Top := edWaptRepoUrl.Top + cbDnsServer.Height + 5 * ScaleY(15);
  edWaptRepoUrl.text := 'unknown';

  labRepo := TLabel.Create(WizardForm);
  labRepo.Parent := CustomPage.Surface; 
  labRepo.Left := edWaptRepoUrl.Left + 5;
  labRepo.Caption := 'example: https://srvwapt.domain.lan/wapt';
  labRepo.Top := edWaptRepoUrl.Top + edWaptRepoUrl.Height + ScaleY(2);


  edWaptServerUrl := TEdit.Create(WizardForm);;
  edWaptServerUrl.Parent := CustomPage.Surface; 
  edWaptServerUrl.Left :=labServer.Left + labServer.Width+5;
  edWaptServerUrl.Width :=CustomPage.SurfaceWidth - cbStaticUrl.Width;
  edWaptServerUrl.Top := edWaptServerUrl.Top + edWaptRepoUrl.Height + 9 * ScaleY(15); 
  edWaptServerUrl.Text := 'unknown';  

  labServer := TLabel.Create(WizardForm);
  labServer.Parent := CustomPage.Surface; 
  labServer.Left := edWaptServerUrl.Left + 5; 
  labServer.Caption := 'example: https://srvwapt.domain.lan';
  labServer.Top := edWaptServerUrl.Top + edWaptServerUrl.Height + ScaleY(2);

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
    edWaptRepoUrl.Text := GetRepoURL('');
    edWaptServerUrl.Text := GetWaptServerURL('');  
    cbDnsServer.Checked := (edWaptRepoUrl.Text='');
    cbStaticUrl.Checked := (edWaptRepoUrl.Text<>'') and (edWaptRepoUrl.Text<>'unknown');
    edDNSDomain.Text := GetDNSDomain('');  

	  //edWaptServerUrl.Visible := IsTaskSelected('use_waptserver');
    //labServer.Visible := edWaptServerUrl.Visible;
  end
end;

function InstallCertCheck:Boolean;
begin
	Result := {#install_certs} <> 0;
end;

function IsWaptAgent:Boolean;
begin
	Result := {#is_waptagent} <> 0;
end;

function RelocateCertDirWaptBase(Param: String):String;
var
  certdir: String;
begin
  certdir := '{#verify_cert}';
  if (pos('c:\tranquilit\wapt',lowercase(certdir))=1) then
    result := ExpandConstant('{app}')+'\'+copy(certdir,length('c:\tranquilit\wapt')+1,255)
  else if (pos('c:\program files (x86)\wapt',lowercase(certdir))=1) then
    result := ExpandConstant('{app}')+'\'+copy(certdir,length('c:\program files (x86)\wapt')+1,255)
  else if (pos('c:\program files\wapt\',lowercase(certdir))=1) then
    result := ExpandConstant('{app}')+'\'+copy(certdir,length('c:\program files\wapt\')+1,255)
  else if (pos('c:\wapt\',lowercase(certdir))=1) then
    result := ExpandConstant('{app}')+'\'+copy(certdir,length('c:\wapt\')+1,255)
  else
    result := certdir;
end;

