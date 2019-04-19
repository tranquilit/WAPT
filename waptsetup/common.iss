#ifndef edition
#error "Preprocessor variable edition must be defined"
#endif

#include "wapt.iss"


[InstallDelete]
#ifndef FastDebug
#ifndef waptenterprise
Type: filesandordirs; Name: "{app}\waptenterprise"
#endif
#endif

[Files]
; sources of installer to rebuild a custom installer (ignoreversion because issc has no version)
#ifndef FastDebug
Source: "innosetup\*"; DestDir: "{app}\waptsetup\innosetup"; Flags: createallsubdirs recursesubdirs ignoreversion;
#endif

#if edition != "waptstarter"
Source: "common.iss"; DestDir: "{app}\waptsetup";
Source: "wapt.iss"; DestDir: "{app}\waptsetup";
Source: "waptsetup.iss"; DestDir: "{app}\waptsetup";
Source: "waptagent.iss"; DestDir: "{app}\waptsetup";
Source: "services.iss"; DestDir: "{app}\waptsetup";
Source: "..\wapt.ico"; DestDir: "{app}";

; sources to regenerate waptupgrade package
Source: "..\waptupgrade\setup.py"; DestDir: "{app}\waptupgrade"; Flags: ignoreversion;
Source: "..\waptupgrade\WAPT\*"; DestDir: "{app}\waptupgrade\WAPT"; Flags: createallsubdirs recursesubdirs ignoreversion;

; global management console
Source: "..\waptconsole.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\waptconsole.exe.manifest"; DestDir: "{app}";

; local management console wapt selfservice
Source: "..\waptself.exe"; DestDir: "{app}"; Flags: ignoreversion

Source: "..\waptdevutils.py"; DestDir: "{app}";
#endif

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

Name: InstallStartPackages; Description: "{cm:InstallStartPackages}";  GroupDescription: "Advanced";  Check: StartPackagesCheck();

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

#if use_fqdn_as_uuid != ""
Filename: {app}\wapt-get.ini; Section: global; Key: use_fqdn_as_uuid; String: {#use_fqdn_as_uuid}; 
#endif

#if edition != "waptserversetup"
Filename: {app}\wapt-get.ini; Section: global; Key: dnsdomain; String: {code:GetDNSDomain}; Check: MustChangeServerConfig;

Filename: {app}\wapt-get.ini; Section: global; Key: max_gpo_script_wait; String: 180; Tasks: DisableHiberboot;
Filename: {app}\wapt-get.ini; Section: global; Key: pre_shutdown_timeout; String: 180; Tasks: DisableHiberboot; 
Filename: {app}\wapt-get.ini; Section: global; Key: hiberboot_enabled; String: {code:Gethiberboot_enabled};

  #if append_host_profiles != ""
Filename: {app}\wapt-get.ini; Section: global; Key: host_profiles; String: {code:GetHostProfiles};
  #endif

  #if set_waptaudit_task_period != ""
Filename: {app}\wapt-get.ini; Section: global; Key: waptaudit_task_period; String: {code:GetWaptauditTaskPeriod};
  #endif

  ; WaptWUA specific settings
  #ifdef waptwua
    #if set_waptwua_enabled != ""
Filename: {app}\wapt-get.ini; Section: waptwua; Key: enabled; String: {#set_waptwua_enabled}; 
    #endif

    #if set_waptwua_default_allow != ""
Filename: {app}\wapt-get.ini; Section: waptwua; Key: default_allow; String: {#set_waptwua_default_allow}; 
    #endif

    #if set_waptwua_offline != ""
Filename: {app}\wapt-get.ini; Section: waptwua; Key: offline; String: {#set_waptwua_offline}; 
    #endif
    
    #if set_waptwua_install_at_shutdown != ""
Filename: {app}\wapt-get.ini; Section: waptwua; Key: install_at_shutdown; String: {#set_waptwua_install_at_shutdown}; 
    #endif

    #if set_waptwua_allow_direct_download != ""
Filename: {app}\wapt-get.ini; Section: waptwua; Key: allow_direct_download; String: {#set_waptwua_allow_direct_download}; 
    #endif
    
    #if set_waptwua_install_delay != ""
Filename: {app}\wapt-get.ini; Section: waptwua; Key: install_delay; String: {#set_waptwua_install_delay}; 
    #endif
    
    #if set_waptwua_download_scheduling != ""
Filename: {app}\wapt-get.ini; Section: waptwua; Key: download_scheduling; String: {#set_waptwua_download_scheduling}; 
    #endif

  #endif
#endif


[Run]
#if edition != "waptserversetup"
Filename: "{app}\wapt-get.exe"; Parameters: "add-upgrade-shutdown"; Flags: runhidden; StatusMsg: {cm:UpdatePkgUponShutdown}; Description: "{cm:UpdatePkgUponShutdown}"

#if edition != "waptstarter"
Filename: "{app}\wapt-get.exe"; Parameters: "--use-gui --direct register"; Flags: runhidden; StatusMsg: {cm:RegisterHostOnServer}; Description: "{cm:RegisterHostOnServer}"
#endif

#if set_start_packages != "" 
Filename: "{app}\wapt-get.exe"; Parameters: "--direct --update-packages install {code:GetStartPackages}"; Tasks: installStartPackages; StatusMsg: {cm:InstallStartPackages}; Description: "{cm:InstallStartPackages} {code:GetStartPackages}"
#else
Filename: "{app}\wapt-get.exe"; Parameters: "--direct update"; Flags: runhidden; StatusMsg: {cm:UpdateAvailablePkg}; Description: "{cm:UpdateAvailablePkg}"
#endif

#endif

[Icons]
Name: "{commonstartup}\WAPT session setup"; Filename: "{app}\wapt-get.exe"; Parameters: "session-setup ALL"; Flags: runminimized excludefromshowinnewinstall;
Name: "{group}\{cm:WAPTConsole}"; Filename: "{app}\waptconsole.exe"; WorkingDir: "{app}"; Check: Not IsWaptAgent();
Name: "{group}\{cm:WAPTSelf}"; Filename: "{app}\waptself.exe"; WorkingDir: "{app}"

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
en.UseWizard=Use Wizard to complete initial configuration steps
en.DontChangeServerSetup=Don't change current setup
en.DNSDetect=Detect WAPT Info with DNS records
en.DNSDomainLookup=DNS Domain to lookup
en.StaticURLS=Static WAPT Informations
en.RunConfigTool=Run congifuration tool
en.WAPTConsole=WAPT Management console
en.WAPTSelf=WAPT Softwares self service

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
fr.RemoveAllFiles=Des fichiers restent présents dans votre répertoire {app} Souhaitez-vous le supprimer ainsi que tous les fichiers qu'il contient ?
fr.UseWizard=Utiliser l'assistant pour achever la phase de configuration initiale.
fr.DontChangeServerSetup=Ne pas modifier la configuration actuelle
fr.DNSDetect=Détecter les URLS WAPT avec des requêtes DNS
fr.DNSDomainLookup=Domaine DNS à  interroger
fr.StaticURLS=URLS WAPT statiques
fr.RunConfigTool=Exécuter l'assistant de configuration
fr.WAPTConsole=Console WAPT
fr.WAPTSelf=Self service logiciels WAPT

;German translation here
de.StartAfterSetup=WAPT Setup-Sitzung bei Sitzungseröffnung starten
de.RegisterHostOnServer=Diesen Computer auf WAPT Server speichern
de.UpdateAvailablePkg=Liste der verfügbaren Pakete auf Main Repostitory aktualisieren
de.UpdatePkgUponShutdown=Packete aktualisieren beim herunterfahren
de.RunConfigTool=Führen Sie das Konfigurationstool aus

[Code]
var
  cbUseWizard, cbDontChangeServer, cbStaticUrl,cbDnsServer: TNewRadioButton;
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

procedure RemoveInstallDir();
var
  installdir: String;
  msg       : String;
  b         : boolean;
begin
  installdir := ExpandConstant('{app}');
  if not DirExists(installdir) then
    exit;

  msg := ExpandConstant('{cm:RemoveAllFiles}');
  msg := ExpandConstant( msg );
  b := ExpandConstant('{param:purge_wapt_dir|0}') = '1';
  b := b or (not runningSilently() and  (MsgBox(msg, mbConfirmation, MB_YESNO) = IDYES) );  // No need to ask if purge_wapt_dir is setted
  if b then
    Deltree(installdir, True, True, True);
end;



#if edition != "waptserversetup"
procedure InitializeWizard;
begin
  CustomPage := CreateCustomPage(wpSelectTasks, 'Installation options', '');
  
  cbUseWizard := TNewRadioButton.Create(WizardForm);
  cbUseWizard.Parent := CustomPage.Surface;
  cbUseWizard.Width := CustomPage.SurfaceWidth;
  cbUseWizard.Caption := ExpandConstant('{cm:UseWizard}');
  cbUseWizard.Onclick := @OnServerClicked;
  #if edition == "waptstarter" || edition == "waptagent"
  cbUseWizard.Visible := False;
  #endif
  
  cbUseWizard.Visible := False;
  cbUseWizard.checked := False;
  
  cbDontChangeServer := TNewRadioButton.Create(WizardForm);
  cbDontChangeServer.Parent := CustomPage.Surface;
  cbDontChangeServer.Width := CustomPage.SurfaceWidth;
  cbDontChangeServer.Caption := ExpandConstant('{cm:DontChangeServerSetup}');
  cbDontChangeServer.Onclick := @OnServerClicked;
  cbDontChangeServer.Top := cbUseWizard.Top + cbUseWizard.Height + 5;
 
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
  cbStaticUrl.Top := cbStaticUrl.Top + cbDnsServer.Height + 5 * ScaleY(15);
  cbStaticUrl.Onclick := @OnServerClicked;

  labRepo := TLabel.Create(WizardForm);
  labRepo.Parent := CustomPage.Surface; 
  labRepo.Left := cbStaticUrl.Left + 14;
  labRepo.Caption := 'Repos URL:';
  labRepo.Top := labRepo.Top + cbDnsServer.Height + 7 * ScaleY(15);
  
  #if edition != "waptstarter"
  labServer := TLabel.Create(WizardForm);
  labServer.Parent := CustomPage.Surface; 
  labServer.Left := cbStaticUrl.Left + 14; 
  labServer.Caption := 'Server URL:';
  labServer.Top := labServer.Top + cbDnsServer.Height + 10 * ScaleY(15);
  #endif

  edWaptRepoUrl := TEdit.Create(WizardForm);
  edWaptRepoUrl.Parent := CustomPage.Surface; 
  edWaptRepoUrl.Left :=labRepo.Left + labRepo.Width + 5;
  edWaptRepoUrl.Width :=CustomPage.SurfaceWidth - cbStaticUrl.Width;
  edWaptRepoUrl.Top := edWaptRepoUrl.Top + cbDnsServer.Height + 7 * ScaleY(15);
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
  edWaptServerUrl.Top := edWaptServerUrl.Top + edWaptRepoUrl.Height + 10 * ScaleY(15); 
  edWaptServerUrl.Text := 'unknown';  

  labServer := TLabel.Create(WizardForm);
  labServer.Parent := CustomPage.Surface; 
  labServer.Left := edWaptServerUrl.Left + 5; 
  labServer.Caption := 'example: https://srvwapt.domain.lan';
  labServer.Top := edWaptServerUrl.Top + edWaptServerUrl.Height + ScaleY(2);
  #endif
end;
#endif



procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  case CurUninstallStep of

    usPostUninstall:
      RemoveInstallDir();

  end;


end;


procedure DeinitializeUninstall();
begin
end;


function InstallCertCheck:Boolean;
var
  value:String;
begin
  value := ExpandConstant('{param:InstallCerts|{#set_install_certs}}');
  Result := value <> '0';
end;

function MustChangeServerConfig:Boolean;
begin
  Result := runningSilently() or (not cbDontChangeServer.Checked and not cbUseWizard.Checked);     
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
    // get supplied StartPackages from commandline, else take hardcoded in setup 
    result := ExpandConstant('{param:StartPackages|{#set_start_packages}}');
    if result = '*' then  
      result := '';
end;

function StartPackagesCheck:Boolean;
begin
  Result := GetStartPackages('') <> '';
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


function LocalWaptServiceIsConfigured() : Boolean;
var
  s : String;
  v : String;
begin
  result := false;
  s:= ExpandConstant('{#emit SetupSetting("AppId")}_is1');
  if not RegQueryStringValue( HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' + s, 'InstallLocation', s ) then
    exit;

  s := s + '\wapt-get.ini';   
  if not FileExists( s ) then
    exit;

  v := GetIniString( 'global', 'wapt_server', '', s );
  if v = '' then
    exit;
  
  v := GetIniString( 'global', 'repo_url', '', s );
  if v = '' then
    exit;

  result := true;
end;

function StrToken(var S: String; Separator: String): String;
var
  I: Integer;
begin
  I := Pos(Separator, S);
  if I <> 0 then
  begin
    Result := Copy(S, 1, I - 1);
    Delete(S, 1,I+Length(Separator)-1);
  end
  else
  begin
    Result := S;
    S := '';
  end;
end;

function GetHostProfiles(param:String):String;
var
  AppendProfiles,NewProfiles,profile: String;
begin
  Result := GetIniString('global', 'host_profiles', '',ExpandConstant('{app}\wapt-get.ini'));
  AppendProfiles := ExpandConstant('{param:append_host_profiles|{#append_host_profiles}}');
  if Result = '' then begin
    if AppendProfiles='*' then
      Result := ''
    else
      Result := AppendProfiles
  end
  else begin
    if AppendProfiles<>'*' then begin
      profile := StrToken(AppendProfiles,',');
      while profile<>'' do begin
         if pos(profile+',',Result+',')<=0 then 
           Result := Result+','+profile;
      end;
    end
  end;
end;

function GetWaptauditTaskPeriod(param:String):String;
begin
  Result := ExpandConstant('{param:waptaudit_task_period|{#set_waptaudit_task_period}}');
end;

procedure PostClickNext();
begin
  PostMessage(WizardForm.NextButton.Handle, $BD11 , 0, 0);
end;  


#if edition != "waptserversetup"
procedure CurPageChanged(CurPageID: Integer);
var
  WaptRepo: String;
  WaptServer: String;
  i : integer;
begin
  case CurPageID of
    wpWelcome:
      begin
      end;
     customPage.Id:
      begin
        edWaptRepoUrl.Text := GetRepoURL('');
        #if edition != "waptstarter"
        edWaptServerUrl.Text := GetWaptServerURL('');  
        #endif
        cbUseWizard.Checked := cbUseWizard.Visible and (GetRepoURL('') = '') and (GetIniString('Global', 'dnsdomain','', ExpandConstant('{app}\wapt-get.ini')) = '');
        cbDontChangeServer.Checked := not cbUseWizard.Checked and not (GetRepoURL('') = '') and (GetIniString('Global', 'dnsdomain','', ExpandConstant('{app}\wapt-get.ini')) = '');
        cbDnsServer.Checked := not cbDontChangeServer.Checked and not cbUseWizard.Checked and (edWaptRepoUrl.Text='');
        cbStaticUrl.Checked := (edWaptRepoUrl.Text<>'') and (edWaptRepoUrl.Text<>'unknown');
        edDNSDomain.Text := GetDNSDomain('');  
        //edWaptServerUrl.Visible := IsTaskSelected('use_waptserver');
        //labServer.Visible := edWaptServerUrl.Visible;
      end;

    wpFinished:
      begin
        //#if edition == "waptsetup"
        //i := WizardForm.RunList.Items.Count 
        //if i = 0 then
        //  exit;
        //i := i - 1;        
        //WizardForm.RunList.Checked[i] := not LocalWaptServiceIsConfigured(); 
        //exit;
        //#endif
              end;
  end;
end;
#endif


