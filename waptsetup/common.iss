#ifndef edition
#error "Preprocessor variable edition must be defined"
#endif

#include "wapt.iss"

[Files]
; sources of installer to rebuild a custom installer (ignoreversion because issc has no version)
#ifndef FastDebug
Source: "innosetup\*"; DestDir: "{app}\waptsetup\innosetup"; Flags: createallsubdirs recursesubdirs ignoreversion;
#endif
Source: "wapt.iss"; DestDir: "{app}\waptsetup";
Source: "waptsetup.iss"; DestDir: "{app}\waptsetup";
Source: "waptagent.iss"; DestDir: "{app}\waptsetup";
Source: "services.iss"; DestDir: "{app}\waptsetup";
Source: "..\wapt.ico"; DestDir: "{app}";

; sources to regenerate waptupgrade package
Source: "..\waptupgrade\setup.py"; DestDir: "{app}\waptupgrade"; Flags: ignoreversion;
Source: "..\waptupgrade\WAPT\*"; DestDir: "{app}\waptupgrade\WAPT"; Flags: createallsubdirs recursesubdirs ignoreversion;

; global management console
Source: "..\waptconsole.exe.manifest"; DestDir: "{app}";
Source: "..\waptconsole.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\waptdevutils.py"; DestDir: "{app}";

; tools
Source: "..\waptwizard.exe"; DestDir: "{app}";
Source: "..\waptwizard.exe.manifest"; DestDir: "{app}";


; authorized public keys
#if set_install_certs == ""
Source: "..\ssl\*"; DestDir: "{app}\ssl"; Tasks: installCertificates; Flags: createallsubdirs recursesubdirs
#else
Source: "..\ssl\*"; DestDir: "{app}\ssl"; Flags: createallsubdirs recursesubdirs; Check: InstallCertCheck();
#endif

Source: "{param:CopyPackagesTrustedCA}"; DestDir: "{app}\ssl"; Flags: external; Check: CopyPackagesTrustedCACheck();
Source: "{param:CopyServersTrustedCA}"; DestDir: "{app}\ssl\server"; Flags: external; Check: CopyServersTrustedCACheck();

[Setup]
#ifdef waptenterprise
OutputBaseFilename={#edition}
#else
OutputBaseFilename={#edition}
#endif
#if edition == 'waptserversetup' 
DefaultDirName=c:\wapt
#else
DefaultDirName={pf32}\wapt
#endif

#if edition != 'waptagent' 
WizardImageFile=..\tranquilit.bmp
#endif

DisableProgramGroupPage=yes

[Languages]
Name:"en"; MessagesFile: "compiler:Default.isl"
Name:"fr";MessagesFile: "compiler:Languages\French.isl"
Name:"de";MessagesFile: "compiler:Languages\German.isl"

[Tasks]
#if edition != "waptserversetup"
Name: DisableHiberboot; Description: "{cm:DisableHiberBoot}"; GroupDescription: "Advanced";
#endif

#if set_install_certs == ""
Name: InstallCertificates; Description: "{cm:InstallSSLCertificates}";  GroupDescription: "Advanced"; Flags: unchecked;
#endif

#if set_start_packages != ""
Name: InstallStartPackages; Description: "{cm:InstallStartPackages}";  GroupDescription: "Advanced";
#endif

#if set_verify_cert == ""
Name: VerifyServerCertificates; Description: "{cm:VerifyServerCertificates}";  GroupDescription: "Advanced";
#endif

#if set_use_kerberos == ""
Name: UseKerberos; Description: "{cm:UseKerberosForRegister}";  GroupDescription: "Advanced";
#endif

[INI]
#if edition != "waptserversetup"
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {code:GetRepoURL}; Check: MustChangeServerConfig;
#endif
Filename: {app}\wapt-get.ini; Section: global; Key: send_usage_report; String:  {#send_usage_report}; 

#if edition != "waptstarter"
Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: 1; 

#if edition != "waptserversetup"
Filename: {app}\wapt-get.ini; Section: global; Key: wapt_server; String: {code:GetWaptServerURL}; Check: MustChangeServerConfig;
#endif

#if set_use_kerberos == ''
Filename: {app}\wapt-get.ini; Section: global; Key: use_kerberos; String: {code:UseKerberosCheck};
#else
Filename: {app}\wapt-get.ini; Section: global; Key: use_kerberos; String: {#set_use_kerberos}; 
#endif

#endif

#if edition != "waptstarter"
Filename: {app}\wapt-get.ini; Section: wapt-templates; Key: repo_url; String: https://store.wapt.fr/wapt;
Filename: {app}\wapt-get.ini; Section: wapt-templates; Key: verify_cert; String: 1;
#endif

Filename: {app}\wapt-get.ini; Section: global; Key: check_certificates_validity; String: {#check_certificates_validity};

; needs to be relocated if waptagent is compiled on another base directory than target computers
#if set_verify_cert != ""
Filename: {app}\wapt-get.ini; Section: global; Key: verify_cert; String: {code:RelocateCertDirWaptBase}; 
#else
Filename: {app}\wapt-get.ini; Section: global; Key: verify_cert; String: {code:VerifyCertCheck}; 
#endif


#if edition != "waptserversetup"
Filename: {app}\wapt-get.ini; Section: global; Key: dnsdomain; String: {code:GetDNSDomain}; Check: MustChangeServerConfig;

Filename: {app}\wapt-get.ini; Section: global; Key: max_gpo_script_wait; String: 180; Tasks: DisableHiberboot;
Filename: {app}\wapt-get.ini; Section: global; Key: pre_shutdown_timeout; String: 180; Tasks: DisableHiberboot; 
Filename: {app}\wapt-get.ini; Section: global; Key: hiberboot_enabled; String: {code:Gethiberboot_enabled};
#endif


[Run]
#if edition != "waptserversetup"
Filename: "{app}\wapt-get.exe"; Parameters: "add-upgrade-shutdown"; Flags: runhidden; StatusMsg: {cm:UpdatePkgUponShutdown}; Description: "{cm:UpdatePkgUponShutdown}"

#if edition != "waptstarter"
Filename: "{app}\wapt-get.exe"; Parameters: "--direct register"; StatusMsg: StatusMsg: {cm:RegisterHostOnServer}; Description: "{cm:RegisterHostOnServer}"
#endif

#if set_start_packages != "" 
Filename: "{app}\wapt-get.exe"; Parameters: "--direct --update install {code:GetStartPackages}"; Tasks: installStartPackages; StatusMsg: {cm:InstallStartPackages}; Description: "{cm:InstallStartPackages}"
#else
Filename: "{app}\wapt-get.exe"; Parameters: "--direct update"; Flags: runhidden; StatusMsg: {cm:UpdateAvailablePkg}; Description: "{cm:UpdateAvailablePkg}"
#endif

#endif

[Icons]
Name: "{commonstartup}\WAPT session setup"; Filename: "{app}\wapt-get.exe"; Parameters: "session-setup ALL"; Flags: runminimized excludefromshowinnewinstall;
Name: "{group}\Console WAPT"; Filename: "{app}\waptconsole.exe"; WorkingDir: "{app}" ; Check: Not IsWaptAgent();
Name: "{group}\Logiciels installés avec WAPT"; Filename: "http://localhost:8088/status"; Check: Not IsWaptAgent();

[CustomMessages]
;English translations here
en.StartAfterSetup=Launch WAPT setup session upon session opening
en.RegisterHostOnServer=Register this computer onto WAPT server
en.UpdateAvailablePkg=Update the list of packages available on the main repository
en.UpdatePkgUponShutdown=Update packages upon shutdown                                   
en.EnableCheckCertificate=Get and enable the check of WaptServer https certificate
en.UseWaptServer=Report computer status to a waptserver and enable remote management
en.InstallSSLCertificates=Install the certificates provided by this installer
en.InstallStartPackages=Install right now the packages {#set_start_packages}
en.UseKerberosForRegister=Use machine kerberos account for registration on WaptServer
en.VerifyServerCertificates=Verify https server certificates
en.DisableHiberBoot=Disable hiberboot, and increase shudown GPO timeout (recommended)
en.RemoveAllFiles=Do you want to delete all remaining files in WAPT directory {app} ?
en.DontChangeServerSetup=Don''t change current setup
en.DNSDetect=Detect WAPT Info with DNS records
en.DNSDomainLookup=DNS Domain to lookup
en.StaticURLS=Static WAPT Info
en.RunConfigTool=Run congifuration tool

;French translations here
fr.StartAfterSetup=Lancer WAPT session setup à l'ouverture de session
fr.RegisterHostOnServer=Enregistre l'ordinateur sur le serveur WAPT
fr.UpdateAvailablePkg=Mise à jour des paquets disponibles sur le dépôt principal
fr.UpdatePkgUponShutdown=Mise à jour des paquets à l'extinction du poste
fr.EnableCheckCertificate=Activer la vérification du certificat https du serveur Wapt
fr.UseWaptServer=Activer l'utilisation d'un serveur Wapt et la gestion centralisée de cet ordinateur
fr.InstallSSLCertificates=Installer les certificats fournis par cet installeur.
fr.InstallStartPackages=Installer maintenant les paquets {#set_start_packages}
fr.UseKerberosForRegister=Utiliser le compte Kerberos de la machine pour l'enregistrement sur le WaptServer
fr.VerifyServerCertificates=Vérifier les certificats https
fr.DisableHiberBoot=Désactiver l'hiberboot, et augmenter le temps pour les GPO (recommandé)
fr.RemoveAllFiles=Des fichiers restent présents dans votre répertoire {app}, souhaitez-vous le supprimer ainsi que tous les fichiers qu''il contient ?'
fr.DontChangeServerSetup=Ne pas modifier la configuration actuelle
fr.DNSDetect=Détecter les URLS WAPT avec des requêtes DNS
fr.DNSDomainLookup=Domaine DNS à interroger
fr.StaticURLS=URLS WAPT statiques
fr.RunConfigTool=Executer l'assitant de configuration

;German translation here
de.StartAfterSetup=WAPT Setup-Sitzung bei Sitzungseröffnung starten
de.RegisterHostOnServer=Diesen Computer auf WAPT Server speichern
de.UpdateAvailablePkg=Liste der verfügbaren Pakete auf Main Repostitory aktualisieren
de.UpdatePkgUponShutdown=Packete aktualisieren beim herunterfahren
de.RunConfigTool=Führen Sie das Konfigurationstool aus

[Code]
var
  cbDontChangeServer, cbStaticUrl,cbDnsServer: TNewRadioButton;
  CustomPage: TWizardPage;
  edWaptServerUrl,edDNSDomain:TEdit;
  labRepo,labServer,labDNSDomain: TLabel;

procedure OnServerClicked(Sender:TObject);
begin
   #if edition != "waptstarter"
   edWaptServerUrl.Enabled:= cbStaticUrl.Checked;
   #endif
   edWaptRepoUrl.Enabled:= cbStaticUrl.Checked;
   edDNSDomain.Enabled := cbDnsServer.Checked;
end;

#if edition != "waptserversetup"
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
#endif

procedure RemoveWaptServer();
begin
  DeleteIniEntry('Global','wapt_server',ExpandConstant('{app}\wapt-get.ini'));
end;

#if edition != "waptserversetup"
procedure InitializeWizard;
begin
  CustomPage := CreateCustomPage(wpSelectTasks, 'Installation options', '');
  
  cbDontChangeServer := TNewRadioButton.Create(WizardForm);
  cbDontChangeServer.Parent := CustomPage.Surface;
  cbDontChangeServer.Width := CustomPage.SurfaceWidth;
  cbDontChangeServer.Caption := ExpandConstant('{cm:DontChangeServerSetup}');
  cbDontChangeServer.Onclick := @OnServerClicked;

  cbDnsServer := TNewRadioButton.Create(WizardForm);
  cbDnsServer.Parent := CustomPage.Surface;
  cbDnsServer.Width := CustomPage.SurfaceWidth;
  cbDnsServer.Caption := ExpandConstant('{cm:DNSDetect}');
  cbDnsServer.Onclick := @OnServerClicked;
  cbDnsServer.Top := cbDontChangeServer.Top + cbDontChangeServer.Height + 5;
  
  labDNSDomain := TLabel.Create(WizardForm);
  labDNSDomain.Parent := CustomPage.Surface; 
  labDNSDomain.Left := cbDnsServer.Left + 14;
  labDNSDomain.Caption := ExpandConstant('{cm:DNSDomainLookup}');
  labDNSDomain.Top := cbDnsServer.Top + cbDnsServer.Height + 5;

  edDNSDomain := TEdit.Create(WizardForm);
  edDNSDomain.Parent := CustomPage.Surface; 
  edDNSDomain.Left := labDNSDomain.Left + labDNSDomain.Width + 5;
  edDNSDomain.Width := CustomPage.SurfaceWidth - labDNSDomain.Width;
  edDNSDomain.Top := labDNSDomain.Top;
  edDNSDomain.text := 'unknown';
  
  cbStaticUrl := TNewRadioButton.Create(WizardForm);
  cbStaticUrl.Parent := CustomPage.Surface; 
  cbStaticUrl.Caption := ExpandConstant('{cm:StaticURLS}');
  cbStaticUrl.Top := cbStaticUrl.Top + cbDnsServer.Height + 3 * ScaleY(15);
  cbStaticUrl.Onclick := @OnServerClicked;

  labRepo := TLabel.Create(WizardForm);
  labRepo.Parent := CustomPage.Surface; 
  labRepo.Left := cbStaticUrl.Left + 14;
  labRepo.Caption := 'Repos URL:';
  labRepo.Top := labRepo.Top + cbDnsServer.Height + 5 * ScaleY(15);
  
  #if edition != "waptstarter"
  labServer := TLabel.Create(WizardForm);
  labServer.Parent := CustomPage.Surface; 
  labServer.Left := cbStaticUrl.Left + 14; 
  labServer.Caption := 'Server URL:';
  labServer.Top := labServer.Top + cbDnsServer.Height + 9 * ScaleY(15);
  #endif

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

  #if edition != "waptstarter"
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
  #endif
end;
#endif



procedure DeinitializeUninstall();
var
    installdir: String;
begin
    installdir := ExpandConstant('{app}');
    if DirExists(installdir) then
    begin
      if (not runningSilently() and  (MsgBox(ExpandConstant('{cm:RemoveAllFiles}'),
               mbConfirmation, MB_YESNO) = IDYES))
               
         or (ExpandConstant('{param:purge_wapt_dir|0}')='1') then
        Deltree(installdir, True, True, True);
    End;
end;


#if edition != "waptserversetup"
procedure CurPageChanged(CurPageID: Integer);
var
  WaptRepo: String;
  WaptServer: String;
begin
  if curPageId=customPage.Id then
  begin
    edWaptRepoUrl.Text := GetRepoURL('');
    #if edition != "waptstarter"
    edWaptServerUrl.Text := GetWaptServerURL('');  
    #endif
    cbDontChangeServer.Checked := (GetRepoURL('') <> '') or (GetIniString('Global', 'dnsdomain','', ExpandConstant('{app}\wapt-get.ini'))<>'');
    cbDnsServer.Checked := not cbDontChangeServer.Checked and (edWaptRepoUrl.Text='');
    cbStaticUrl.Checked := (edWaptRepoUrl.Text<>'') and (edWaptRepoUrl.Text<>'unknown');
    edDNSDomain.Text := GetDNSDomain('');  

	  //edWaptServerUrl.Visible := IsTaskSelected('use_waptserver');
    //labServer.Visible := edWaptServerUrl.Visible;
  end
end;
#endif


function InstallCertCheck:Boolean;
var
  value:String;
begin
  value := ExpandConstant('{param:InstallCerts|{#set_install_certs}}');
  Result := value <> '0';
end;

function MustChangeServerConfig:Boolean;
begin
  Result := runningSilently() or not cbDontChangeServer.Checked;     
end;

function UseKerberosCheck(param:String):String;
begin
  if IsTaskSelected('UseKerberos') then
     Result := '1'
  else
     Result := '0';
end;

function VerifyCertCheck(param:String):String;
begin
  if IsTaskSelected('VerifyServerCertificates') then
     Result := '1'
  else
     Result := '0'
end;

function Gethiberboot_enabled(param:String):String;
begin
  // get supplied verify_cert from commandline, else take hardcoded in setup 
  Result := ExpandConstant('{param:DisableHiberBoot|{#set_disable_hiberboot}}');
  if Result = '' then
    if IsTaskSelected('DisableHiberBoot') then
       Result := '0'
    else
       Result := '1'
end;

function GetStartPackages(Param: String):String;
begin
    // get suuplied StartPackages from commandline, else take hardcoded in setup 
    result := ExpandConstant('{param:StartPackages|{#set_start_packages}}');
end;


function IsWaptAgent:Boolean;
begin
  Result := '{#edition}' = 'waptagent';
end;

function RelocateCertDirWaptBase(Param: String):String;
var
  certdir: String;
begin
  // get supplied verify_cert from commandline, else take hardcoded in setup 
  certdir := ExpandConstant('{param:verify_cert|{#set_verify_cert}}');
  if (certdir<>'0') and (certdir<>'1') and (lowercase(certdir)<>'true') and (lowercase(certdir)<>'false') then
  begin
      if (pos('c:\tranquilit\wapt',lowercase(certdir))=1) then
        result := ExpandConstant('{app}')+'\'+copy(certdir,length('c:\tranquilit\wapt')+1,255)
      else if (pos('c:\program files (x86)\wapt',lowercase(certdir))=1) then
        result := ExpandConstant('{app}')+'\'+copy(certdir,length('c:\program files (x86)\wapt')+1,255)
      else if (pos('c:\program files\wapt\',lowercase(certdir))=1) then
        result := ExpandConstant('{app}')+'\'+copy(certdir,length('c:\program files\wapt\')+1,255)
      else if (pos('c:\wapt\',lowercase(certdir))=1) then
        result := ExpandConstant('{app}')+'\'+copy(certdir,length('c:\wapt\')+1,255)
      else if copy(certdir,2,1) <> ':' then
        // relative path to wapt base dir
        result := ExpandFileName(ExpandConstant('{app}')+'\'+certdir)
      else
        // absolute
        result := certdir;
  end
  else
    result := certdir;
  
end;


function CopyPackagesTrustedCACheck:Boolean;
var
  value: String;
begin
  value := ExpandConstant('{param:CopyPackagesTrustedCA}')
  Result := (value <> '') and (value<>'0');     
end;

function CopyServersTrustedCACheck:Boolean;
var
  value: String;
begin
  value := ExpandConstant('{param:CopyServersTrustedCA}')
  Result := (value <> '') and (value<>'0');     
end;


