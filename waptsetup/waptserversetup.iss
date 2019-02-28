#define waptserver
#define edition "waptserversetup"
#define AppName "WAPT Server"
#define default_repo_url "http://127.0.0.1/wapt/"
#define default_wapt_server "http://127.0.0.1"

#define repo_url ""
#define wapt_server ""

#define output_dir "."
#define Company "Tranquil IT Systems"

#define send_usage_report "1"

; if not empty, set value 0 or 1 will be defined in wapt-get.ini
#define set_use_kerberos "0"

; if empty, a task is added
; copy authorized package certificates (CA or signers) in <wapt>\ssl
#define set_install_certs "0"

; if 1, expiry and CRL of package certificates will be checked
#define check_certificates_validity "1"

; if not empty, the 0, 1 or path to a CA bundle will be defined in wapt-get.ini for checking of https certificates
#define set_verify_cert "0"

; default value for detection server and repo URL using dns 
#define default_dnsdomain ""

; if not empty, a task will propose to install this package or list of packages (comma separated)
#define set_start_packages ""

; if not empty, the host will inherit these (comma separated) list of profile packages.
#define append_host_profiles ""

#define vcredist

;#define signtool "kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f"

#ifndef set_disable_hiberboot
#define set_disable_hiberboot ""
#endif

#define use_fqdn_as_uuid ""

#ifdef waptenterprise
  #define set_waptwua_enabled ""
  #define set_waptwua_default_allow ""
  #define set_waptwua_offline ""
  #define set_waptwua_allow_direct_download ""
  #define set_waptwua_install_delay ""
  #define set_waptwua_download_scheduling ""
#endif

; for fast compile in developent mode
;#define FastDebug

;#define choose_components

#include "common.iss"

[Files]

#ifndef FastDebug
; server postconf utility
#ifdef choose_components
Source: "..\waptserverpostconf.exe"; DestDir: "{app}"; Flags: ignoreversion; Tasks: InstallWaptserver
#else
Source: "..\waptserverpostconf.exe"; DestDir: "{app}"; Flags: ignoreversion;
#endif
Source: "..\waptserverpostconf.exe.manifest"; DestDir: "{app}";

; deployment/upgrade tool
Source: "..\waptdeploy.exe"; DestDir: "{app}\waptserver\repository\wapt\"; Flags: ignoreversion

Source: "..\runwaptservice.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\runwaptserver.bat"; DestDir: "{app}"; Flags: ignoreversion

#ifdef choose_components
Source: "..\waptserver\waptserver.ini.template"; DestDir: "{app}\conf"; DestName: "waptserver.ini.template"; Tasks: InstallWaptserver
Source: "..\waptserver\*.py"; DestDir: "{app}\waptserver"; Tasks: InstallWaptserver       
Source: "..\waptserver\*.bat"; DestDir: "{app}\waptserver"; Tasks: InstallWaptserver       
Source: "..\waptserver\*.template"; DestDir: "{app}\waptserver"; Tasks: InstallWaptserver
Source: "..\waptserver\static\*"; DestDir: "{app}\waptserver\static"; Flags: createallsubdirs recursesubdirs; Tasks: InstallWaptserver
Source: "..\waptserver\templates\*"; DestDir: "{app}\waptserver\templates"; Flags: createallsubdirs recursesubdirs; Tasks: InstallWaptserver
Source: "..\waptserver\translations\*"; DestDir: "{app}\waptserver\translations"; Flags: createallsubdirs recursesubdirs; Tasks: InstallWaptserver
Source: "..\waptserver\scripts\*"; DestDir: "{app}\waptserver\scripts"; Flags: createallsubdirs recursesubdirs; Tasks: InstallWaptserver
Source: "..\waptserver\pgsql-9.6\*"; DestDir: "{app}\waptserver\pgsql-9.6"; Flags: createallsubdirs recursesubdirs; Tasks: InstallPostgreSQL
Source: "..\waptserver\nginx\*"; DestDir: "{app}\waptserver\nginx"; Flags: createallsubdirs recursesubdirs; Tasks: InstallNGINX
Source: "..\waptserver\mongodb\mongoexport.exe"; DestDir: "{app}\waptserver\mongodb"; Check: DirExists(ExpandConstant('{app}\waptserver\mongodb'));  Tasks: InstallWaptserver

; waptenterprise only
#ifdef waptenterprise
Source: "..\waptenterprise\waptserver\*"; DestDir: "{app}\waptenterprise\waptserver\";  Flags: createallsubdirs recursesubdirs;Tasks: InstallWaptserver
#endif

#else
Source: "..\waptserver\waptserver.ini.template"; DestDir: "{app}\conf"; DestName: "waptserver.ini.template";
Source: "..\waptserver\*.py"; DestDir: "{app}\waptserver";   
Source: "..\waptserver\*.bat"; DestDir: "{app}\waptserver";   
Source: "..\waptserver\*.template"; DestDir: "{app}\waptserver"; 
Source: "..\waptserver\static\*"; DestDir: "{app}\waptserver\static"; Flags: createallsubdirs recursesubdirs;
Source: "..\waptserver\templates\*"; DestDir: "{app}\waptserver\templates"; Flags: createallsubdirs recursesubdirs;
Source: "..\waptserver\translations\*"; DestDir: "{app}\waptserver\translations"; Flags: createallsubdirs recursesubdirs; 
Source: "..\waptserver\scripts\*"; DestDir: "{app}\waptserver\scripts"; Flags: createallsubdirs recursesubdirs;
Source: "..\waptserver\pgsql-9.6\*"; DestDir: "{app}\waptserver\pgsql-9.6"; Flags: createallsubdirs recursesubdirs;
Source: "..\waptserver\nginx\*"; DestDir: "{app}\waptserver\nginx"; Flags: createallsubdirs recursesubdirs;
Source: "..\waptserver\mongodb\mongoexport.exe"; DestDir: "{app}\waptserver\mongodb"; Check: DirExists(ExpandConstant('{app}\waptserver\mongodb'))

; waptenterprise only
#ifdef waptenterprise
Source: "..\waptenterprise\waptserver\*"; DestDir: "{app}\waptenterprise\waptserver\";  Flags: createallsubdirs recursesubdirs;
#endif

#endif
#endif  
 ;fastdebug


[Dirs]
Name: "{app}\waptserver\repository"
Name: "{app}\waptserver\log"
Name: "{app}\waptserver\repository\wapt"
Name: "{app}\waptserver\repository\wapt-host"
Name: "{app}\waptserver\repository\wapt-group"
Name: "{app}\waptserver\repository\waptwua"
Name: "{app}\waptserver\nginx\ssl"

[InstallDelete]
Type: files; Name: "{app}\waptserver\*.pyc"

[INI]
Filename: {app}\conf\waptserver.ini; Section: options; Key: allow_unauthenticated_registration; String: True;
; Filename: {app}\wapt-get.ini; Section: Global; Key: default_package_prefix; String: "{code:GetDefaultPackagePrefix}"; Check: CheckSetDefaultPackagePrefix(); 

[RUN]
Filename: "{app}\waptserver\pgsql-9.6\vcredist_x64.exe"; Parameters: "/passive /quiet"; StatusMsg: {cm:InstallMSVC2013}; Description: "{cm:InstallMSVC2013}";  
Filename: "{app}\wapt-get.exe"; Parameters: " update-packages {app}\waptserver\repository\wapt"; Flags: runhidden; StatusMsg: {cm:ScanPackages}; Description: "{cm:ScanPackages}"
Filename: "{app}\waptpython.exe"; Parameters: "{app}\waptserver\winsetup.py all -c {app}\conf\waptserver.ini -f --setpassword={code:GetServerPassword}"; StatusMsg: {cm:InstallingServerServices}; Description: "{cm:InstallingServerServices}"
Filename: "net"; Parameters: "start waptpostgresql"; Flags: runhidden; StatusMsg: "Starting service waptpostgresql"
Filename: "net"; Parameters: "start waptnginx"; Flags: runhidden; StatusMsg: "Starting service waptnginx"
Filename: "net"; Parameters: "start waptserver"; Flags: runhidden; StatusMsg: "Starting service waptserver"
#ifdef waptenterprise
Filename: "net"; Parameters: "start wapttasks"; Flags: runhidden; StatusMsg: "Starting service wapttasks"
#endif

Filename: "{app}\wapt-get.exe"; Parameters: "register --wapt-server-url={code:GetWaptServerURL} --wapt-repo-url={code:GetWaptRepoURL} --use-gui --update "; Flags: runhidden; Description: {cm:SetupRegisterThisComputer}; Check: CheckRegisterUpdate(); Tasks: RegisterComputerOnLocalServer;
;Filename: "{app}\wapt-get.exe"; Parameters: "create-keycert /CommonName={code:GetCertificateCommonName} /PrivateKeyPassword={code:GetPrivateKeyPassword}"; Description: {cm:CreatePackageRSAKeyCert}; Check: IsPersonalcertificateDefined();
;Filename: "{app}\wapt-get.exe"; Parameters: "build-waptagent /ConfigFilename={app}\wapt-get.ini /PrivateKeyPassword={code:GetPrivateKeyPassword}"; Description: {cm:CreateWaptAgentInstaller}; StatusMsg: {cm:CreateWaptAgentInstaller}; 

Filename: "{app}\waptconsole.exe"; Parameters: "--lang {language}"; Flags: postinstall skipifsilent shellexec; StatusMsg: {cm:StartWaptconsole}; Description: "{cm:StartWaptconsole}"
Filename: {cm:InstallDocURL}; Flags: postinstall skipifsilent shellexec; StatusMsg: {cm:OpenWaptDocumentation}; Description: "{cm:OpenWaptDocumentation}"

[Tasks]
#ifdef choose_components
Name: InstallNGINX; Description: "{cm:InstallNGINX}"; GroupDescription: "WAPT Server"
Name: InstallPostgreSQL; Description: "{cm:InstallPostgreSQL}"; GroupDescription: "WAPT Server"
Name: InstallWaptserver; Description: "{cm:InstallWaptServer}"; GroupDescription: "WAPT Server"
#endif
Name: RegisterComputerOnLocalServer; Description: "{cm:SetupRegisterThisComputer}";

[UninstallRun]
#ifdef waptenterprise
Filename: "net"; Parameters: "stop waptnginx"; Flags: runhidden; StatusMsg: "Stopping service waptnginx"
Filename: "net"; Parameters: "stop waptserver"; Flags: runhidden; StatusMsg: "Stopping service waptserver"
Filename: "net"; Parameters: "stop wapttasks"; Flags: runhidden; StatusMsg: "Stopping service wapttasks"
Filename: "net"; Parameters: "stop waptpostgresql"; Flags: runhidden; StatusMsg: "Stopping service waptpostgresql"
Filename: "sc";  Parameters: "delete waptserver"; Flags: runhidden; StatusMsg: "Removing service waptserver"
Filename: "sc";  Parameters: "delete waptnginx"; Flags: runhidden; StatusMsg: "Removing service waptnginx"
Filename: "sc";  Parameters: "delete waptpostgresql"; Flags: runhidden; StatusMsg: "Removing service waptpostgresql"
Filename: "sc";  Parameters: "delete wapttasks"; Flags: runhidden; StatusMsg: "Removing service wapttasks"
#else
Filename: "net"; Parameters: "stop waptnginx"; Flags: runhidden; StatusMsg: "Stopping service waptnginx"
Filename: "net"; Parameters: "stop waptserver"; Flags: runhidden; StatusMsg: "Stopping service waptserver"
Filename: "net"; Parameters: "stop waptpostgresql"; Flags: runhidden; StatusMsg: "Stopping service waptpostgresql"
Filename: "sc";  Parameters: "delete waptserver"; Flags: runhidden; StatusMsg: "Removing service waptserver"
Filename: "sc";  Parameters: "delete waptnginx"; Flags: runhidden; StatusMsg: "Removing service waptnginx"
Filename: "sc";  Parameters: "delete waptpostgresql"; Flags: runhidden; StatusMsg: "Removing service waptpostgresql"
#endif

[CustomMessages]
fr.RegisteringService=Mise en place du service WaptServer
fr.InstallMSVC2013=Installation de MSVC++ 2013 Redistribuable
fr.LaunchingPostconf=Lancement de la post-configuration du serveur
fr.InstallNGINX=Installer le serveur http NGINX (utlise les ports 80 et 443)
fr.InstallPostgreSQL=Installer le serveur PostgreSQL
fr.InstallWaptServer=Installer le serveur Wapt
fr.ScanPackages=Scan des paquets actuels
fr.InstallingServerServices=Installation des services Serveur
fr.SpecifyServerPassword=Choisissez un mot de passe pour le compte admin Wapt
fr.BothPasswordsDontMatch=Les mots de passe saisis ne correpondent pas
fr.WaptAdminPassword=Mot de passe Admin du serveur WAPT
fr.ConfirmPassword=Confirmer le mot de passe
fr.OpenWaptDocumentation=Afficher la documentation d'installation
fr.InstallDocURL=https://doc.wapt.fr
fr.SetupRegisterThisComputer=Enregistrer cette machine sur ce nouveau serveur Wapt
fr.CreatePackageRSAKeyCert=Créer une clé et un certificat pour les paquets
fr.CreateWaptAgentInstaller=Générer un installeur WaptAgent personnalisé pour les postes clients
fr.WaptServerHostName=Nom d'hôte du serveur WAPT
fr.PackagesPrefix=Préfixe de paquets
fr.PersonalKeyname=Nom de clé personnelle
fr.PersonalEmail=Courriel à intégrer au certificat
fr.PersonalKeyPassword=Mot de passe de la clé privée
fr.PersonalKeyConfirmPassword=Confirmer le mot de passe
fr.StartWaptconsole=Lancer Waptconsole

en.RegisteringService=Setup WaptServer Service
en.InstallMSVC2013=Installing MSVC++ 2013 Redistribuable
en.LaunchingPostconf=Launch server post-configuration
en.InstallNGINX=Install NGINX http server(will use ports 80 and 443)
en.InstallPostgreSQL=Install PostgreSQL Server
en.InstallWaptServer=Install Wapt server
en.ScanPackages=Scan packages
en.InstallingServerServices=Installing Server services...
en.SpecifyServerPassword=Please specify a password for the Wapt admin account
en.BothPasswordsDontMatch=Passwords entries are not matching
en.WaptAdminPassword=WAPT Server Admin password
en.ConfirmPassword=Confirm password
en.OpenWaptDocumentation=Show installation documentation
en.InstallDocURL=https://doc.wapt.fr
en.SetupRegisterThisComputer=Register this computer on this new Wapt server
en.CreatePackageRSAKeyCert=Build a key and a certificate for packages signature
en.CreateWaptAgentInstaller=Build a customized WaptAgent installer for client computers
en.WaptServerHostName=WAPT Server Hostname
en.PackagesPrefix=Packages prefix
en.PersonalKeyname=Personal key name
en.PersonalEmail=Personal Email to embed in certificate
en.PersonalKeyPassword=Personal key password
en.PersonalKeyConfirmPassword=Confirm password
en.StartWaptconsole=Run Waptconsole

de.RegisteringService=Setup WaptServer Service
de.InstallMSVC2013=MSVC++ 2013 Redistribuable installieren
de.LaunchingPostconf=Server Post-Konfiguration starten
de.InstallNGINX=NGINX installieren http Server
de.InstallPostgreSQL=PostgreSQL Server installieren
de.InstallWaptServer=Wapt server installieren
de.ScanPackages=Scan packages
de.SpecifyServerPassword=Please specify a password for the Wapt admin account
de.BothPasswordsDontMatch=Passwords entries are not matching
de.WaptAdminPassword=WAPT Server Admin password (leave blank to not change password)
de.ConfirmPassword=Confirm password
de.OpenWaptDocumentation=Show installation documentation
de.InstallDocURL=https://doc.wapt.fr
de.SetupRegisterThisComputer=Register this computer on this new Wapt server
de.CreatePackageRSAKeyCert=Build a key and a certificate for packages signature
de.CreateWaptAgentInstaller=Build a customized WaptAgent installer for client computers
de.WaptServerHostName=WAPT Server Hostname
de.PackagesPrefix=Packages prefix
de.PersonalKeyname=Personal key name
de.PersonalEmail=Personal Email to embed in certificate
de.PersonalKeyPassword=Personal key password
de.PersonalKeyConfirmPassword=Confirm password
de.StartWaptconsole=Run Waptconsole

[InstallDelete]
Type: files; Name: "{app}\waptserver\waptserver.py*"

[Files]
Source: "..\waptsetuputil.dll"; Flags: dontcopy

[Code]
var
    pgServerParams:TInputQueryWizardPage;
    pgPersonalKeyOptions:TInputOptionWizardPage;
    pgPersonalKeyParams:TInputQueryWizardPage;
    pgPersonalKeyChoose:TInputFileWizardPage;
    pgPackagesParams:TInputQueryWizardPage;
    pgBuildWaptAgentOptions:TInputOptionWizardPage;

function GetComputerDNSName:PAnsiChar; external 'GetComputerDNSName@files:waptsetuputil.dll stdcall';
function GetComputerConnectedIP:PAnsiChar; external 'GetComputerConnectedIP@files:waptsetuputil.dll stdcall';
function GetComputerDNSNameOrIP:PAnsiChar; external 'GetComputerDNSNameOrIP@files:waptsetuputil.dll stdcall';
function GetWaptServerOrComputerDNSNameOrIP:PAnsiChar; external 'GetWaptServerOrComputerDNSNameOrIP@files:waptsetuputil.dll stdcall';

const Codes64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function Encode64(S: AnsiString): AnsiString;
var
	i: Integer;
	a: Integer;
	x: Integer;
	b: Integer;
begin
	Result := '';
	a := 0;
	b := 0;
	for i := 1 to Length(s) do
	begin
		x := Ord(s[i]);
		b := b * 256 + x;
		a := a + 8;
		while (a >= 6) do
		begin
			a := a - 6;
			x := b div (1 shl a);
			b := b mod (1 shl a);
			Result := Result + copy(Codes64,x + 1,1);
		end;
	end;
	if a > 0 then
	begin
		x := b shl (6 - a);
		Result := Result + copy(Codes64,x + 1,1);
	end;
	a := Length(Result) mod 4;
	if a = 2 then
		Result := Result + '=='
	else if a = 3 then
		Result := Result + '=';

end;

function Decode64(S: AnsiString): AnsiString;
var
	i: Integer;
	a: Integer;
	x: Integer;
	b: Integer;
begin
	Result := '';
	a := 0;
	b := 0;
	for i := 1 to Length(s) do
	begin
		x := Pos(s[i], codes64) - 1;
		if x >= 0 then
		begin
			b := b * 64 + x;
			a := a + 6;
			if a >= 8 then
			begin
				a := a - 8;
				x := b shr a;
				b := b mod (1 shl a);
				x := x mod 256;
				Result := Result + chr(x);
			end;
		end
	else
		Exit; // finish at unknown
	end;
end;


// Encode password in base64
function GetServerPassword(Param: String):String;
begin
  if (pgServerParams.Values[1]<>'') and (pgServerParams.Values[1] = pgServerParams.Values[2]) then
    Result := Encode64(pgServerParams.Values[1])
  else
    Result := Encode64('');
end;

function GetDefaultPackagePrefix(Param: String):String;
begin
  Result := pgPackagesParams.Values[0];
end;

function GetCertificateCommonName(Param: String):String;
begin
  if (pgPersonalKeyParams.Values[0]<>'') then
    Result := Encode64(pgPersonalKeyParams.Values[0])
  else
    Result := Encode64('')
end;

function GetPrivateKeyPassword(Param: String):String;
begin
  if (pgPackagesParams.Values[1]<>'') then
    Result := Encode64(pgPackagesParams.Values[1])
  else
    Result := Encode64('')
end;

function CheckSetDefaultPackagePrefix:Boolean;
begin
  Result := pgPackagesParams.Values[0]<>'';
end;

function GetWaptServerURL(Param: String):String;
begin
  if pgServerParams.Values[0]<>'' then
    Result := 'https://'+pgServerParams.Values[0]
  else
    Result := GetIniString('global','wapt_server','',ExpandConstant('{app}\wapt-get.ini'));
end;

function GetWaptRepoURL(Param: String):String;
begin
  if pgServerParams.Values[0]<>'' then
    Result := 'https://'+pgServerParams.Values[0]+'/wapt'
  else
    Result := GetIniString('global','repo_url','',ExpandConstant('{app}\wapt-get.ini'));
end;

function CheckRegisterUpdate:Boolean;
begin
  result := GetWaptServerURL('')<>'';
end;

function GetPersonalCertificatePath(Param: String):String;
begin
  case pgPersonalKeyOptions.SelectedValueIndex of 
    0: Result := GetIniString('global','personal_certificate_path','',ExpandConstant('{app}\wapt-get.ini'));
    1: Result := pgPersonalKeyChoose.Values[0];
    2: Result := pgPersonalKeyChoose.Values[0];
  else
    Result := '';
  end;
end;


procedure SetControlCursor(oCtrl: TControl; oCurs: TCursor);
var 
  i     : Integer;
  oCmp  : TComponent;
begin
  oCtrl.Cursor := oCurs;
  for i := 0 to oCtrl.ComponentCount-1 do
  begin
    oCmp := oCtrl.Components[i];
    if oCmp is TControl then
    begin
      SetControlCursor(TControl(oCmp), oCurs);
    end;
  end;
end;


procedure OnServerParamsActivate(Sender: TWizardPage);
begin
end;

procedure OnPersonalKeyChooseActivate(Sender: TWizardPage);
begin
end;

procedure OnPersonalKeyOptionsActivate(Sender: TWizardPage);
begin
end;

function OnPersonalKeyChooseShouldSkipPage(Sender: TWizardPage): Boolean;
begin
  Result := pgPersonalKeyOptions.SelectedValueIndex<>1; 
end;

function OnPersonalKeyParamsNextButtonClick(Sender: TWizardPage): Boolean;
begin
  if (pgPersonalKeyParams.Values[0] = '') then 
      RaiseException('Please specify a keyname');

  if (pgPersonalKeyParams.Values[2] = '') then 
      RaiseException('Please specify a password to encrypt the personal key');

  if (pgPersonalKeyParams.Values[2] <> pgPersonalKeyParams.Values[3]) then 
      RaiseException('Both passwords don''t match');

  // Generate 

  Result := True;
end;


function OnPersonalKeyParamsShouldSkipPage(Sender: TWizardPage): Boolean;
begin
  Result := pgPersonalKeyOptions.SelectedValueIndex<>2; 
end;

function OnPackagesParamsNextButtonClick(Sender: TWizardPage): Boolean;
begin
  if pgPackagesParams.Values[0] = '' then 
    RaiseException('You must specify a packages prefix');
  if pgPackagesParams.Values[1] = '' then 
    RaiseException('You must specify the private key password to check and build Agent');
  MsgBox('Lancement vérification de la clé pour le certificat '+GetPersonalCertificatePath('')+' and prefix '+pgPackagesParams.Values[0], mbInformation, MB_OK);  
  Result := True;
end;


function OnServerParamsNextButtonClick(Sender: TWizardPage): Boolean;
begin
  if pgServerParams.Values[0] = '' then 
    RaiseException('You must specify a server name or IP');
  if pgServerParams.Values[1] = '' then 
    RaiseException('You must specify a server password');
  if pgServerParams.Values[1] <> pgServerParams.Values[2]  then 
    RaiseException('Server passwords don''t match');
  Result := True;
end;

function OnPackagesParamsShouldSkipPage(Sender: TWizardPage): Boolean;
begin
  // todo skip if no install
  Result := False; 
end;

procedure OnPackagesParamsActivate(Sender: TWizardPage);
begin
  // read key password
  if pgPackagesParams.Values[1] = '' then
    pgPackagesParams.Values[1] := pgPersonalKeyParams.Values[2];
end;


procedure OnBuildWaptAgentOptionsActivate(Sender: TWizardPage);
begin
end;

procedure InitializeWizard;
begin
  pgServerParams := CreateInputQueryPage(wpSelectTasks,'Server Params',
    'WAPT parameters',
    'Please specify the parameters for your Wapt install, then click Next.');
  pgServerParams.Add(ExpandConstant('{cm:WaptServerHostName}'),False);
  pgServerParams.Add(ExpandConstant('{cm:WaptAdminPassword}'),True);
  pgServerParams.Add(ExpandConstant('{cm:ConfirmPassword}'),True);
  pgServerParams.OnActivate := @OnServerParamsActivate;
  pgServerParams.OnNextButtonClick := @OnServerParamsNextButtonClick;

  (*
  pgPersonalKeyOptions := CreateInputOptionPage(pgServerParams.ID,'Personal key / certificate',
      'Choose wether you want to (re)create a pair of keys / certificate to sign your packages', '',True,False);
  pgPersonalKeyOptions.Add('Skip');
  pgPersonalKeyOptions.Add('Pick an existing certificate (.crt)');
  pgPersonalKeyOptions.Add('Create a new self signed certificate / private key');
  pgPersonalKeyOptions.OnActivate := @OnPersonalKeyOptionsActivate;
   

  // Choose an existing certificate
  pgPersonalKeyChoose := CreateInputFilePage(pgPersonalKeyOptions.ID,'Personal key / certificate', 'Select your existing certificate','');
  pgPersonalKeyChoose.Add('Location of personal certificate file:','X509 PEM encoded certificate|*.crt|All files|*.*','.crt');
  pgPersonalKeyChoose.Values[0] := '';
  pgPersonalKeyChoose.IsSaveButton[0] := False;
  pgPersonalKeyChoose.OnActivate := @OnPersonalKeyChooseActivate;
  pgPersonalKeyChoose.OnShouldSkipPage := @OnPersonalKeyChooseShouldSkipPage;

  // Specify key /certificate paramaters
  pgPersonalKeyParams := CreateInputQueryPage(pgPersonalKeyChoose.ID,'Personal key / certificate',
    'Certificate / key parameters',
    'Please specify the parameters for the certificate/key initialization, then click Next to process.');
  pgPersonalKeyParams.Add(ExpandConstant('{cm:PersonalKeyname}'),False);
  pgPersonalKeyParams.Add(ExpandConstant('{cm:PersonalEmail}'),False);
  pgPersonalKeyParams.Add(ExpandConstant('{cm:PersonalKeyPassword}'),True);
  pgPersonalKeyParams.Add(ExpandConstant('{cm:PersonalKeyConfirmPassword}'),True);
  pgPersonalKeyParams.OnShouldSkipPage := @OnPersonalKeyParamsShouldSkipPage;
  pgPersonalKeyParams.OnNextButtonClick := @OnPersonalKeyParamsNextButtonClick;

  // package prefix and password to check key
  pgPackagesParams := CreateInputQueryPage(pgPersonalKeyParams.ID,'Packages design parameters',
    'Parameters used when creating / importing packages and for upgrade package.',
    'Packages prefix is a simple tring (like test) which is appended in front of packages name to identify the source'#13#10'Key password will be tested and used in next step to build an upgrade package');
  pgPackagesParams.Add(ExpandConstant('{cm:PackagesPrefix}'),False);
  pgPackagesParams.Add(ExpandConstant('{cm:PersonalKeyPassword}'),True);
  pgPackagesParams.OnActivate := @OnPackagesParamsActivate;
  pgPackagesParams.OnShouldSkipPage := @OnPackagesParamsShouldSkipPage;
  pgPackagesParams.OnNextButtonClick := @OnPackagesParamsNextButtonClick;

  pgBuildWaptAgentOptions := CreateInputOptionPage(pgPackagesParams.ID,'Waptagent build','',
      'Choose wether you want to (re)create the waptagent installer for this version of Wapt',True,False);
  pgBuildWaptAgentOptions.Add('Skip');
  pgBuildWaptAgentOptions.Add('Compile a customized waptagent installer and waptupgrade package');
  pgBuildWaptAgentOptions.OnActivate := @OnBuildWaptAgentOptionsActivate;
  *)

end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  CertFilename: String;
begin
  case CurPageID of
    wpSelectTasks:
      begin
        Result := true;
        pgServerParams.Values[0] := GetWaptServerOrComputerDNSNameOrIP;

        (*CertFilename := GetIniString('global','personal_certificate_path','',ExpandConstant('{app}\wapt-get.ini'));
        if (CertFilename<>'') and (FileExists(CertFilename)) then 
          pgPersonalKeyOptions.SelectedValueIndex := 0
        else
          pgPersonalKeyOptions.SelectedValueIndex := 2;

        if CertFilename <> '' then
          pgPersonalKeyChoose.Values[0] := CertFilename
        else
          pgPersonalKeyChoose.Values[0] := 'c:\private';

        pgPackagesParams.Values[0] := GetIniString('global','default_package_prefix','test',ExpandConstant('{app}\wapt-get.ini'));
        *)
      end;
  else
    Result := True;
  end;
end;
   
