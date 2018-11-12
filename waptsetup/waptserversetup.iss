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

; for fast compile in developent mode
;#define FastDebug

;#define choose_components

#include "common.iss"

[Files]

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


[RUN]
Filename: "{app}\waptserver\pgsql-9.6\vcredist_x64.exe"; Parameters: "/passive /quiet"; StatusMsg: {cm:InstallMSVC2013}; Description: "{cm:InstallMSVC2013}";  
Filename: "{app}\wapt-get.exe"; Parameters: " update-packages {app}\waptserver\repository\wapt"; Flags: runhidden; StatusMsg: {cm:ScanPackages}; Description: "{cm:ScanPackages}"
Filename: "{app}\waptpython.exe"; Parameters: "{app}\waptserver\winsetup.py all -c {app}\conf\waptserver.ini -f --setpassword={code:GetServerPassword}"; StatusMsg: {cm:ScanPackages}; Description: "{cm:InstallingServerServices}"
Filename: "net"; Parameters: "start waptpostgresql"; Flags: runhidden; StatusMsg: "Starting service waptpostgresql"
Filename: "net"; Parameters: "start waptnginx"; Flags: runhidden; StatusMsg: "Starting service waptnginx"
Filename: "net"; Parameters: "start waptserver"; Flags: runhidden; StatusMsg: "Starting service waptserver"
#ifdef waptenterprise
Filename: "net"; Parameters: "start wapttasks"; Flags: runhidden; StatusMsg: "Starting service wapttasks"
#endif
Filename: "{app}\waptserverpostconf.exe"; Parameters: "--lang {language}"; Flags: postinstall runascurrentuser skipifsilent shellexec; StatusMsg: {cm:RunConfigTool}; Description: "{cm:RunConfigTool}"

[Tasks]
#ifdef choose_components
Name: InstallNGINX; Description: "{cm:InstallNGINX}"; GroupDescription: "WAPTServer"
Name: InstallPostgreSQL; Description: "{cm:InstallPostgreSQL}"; GroupDescription: "WAPTServer"
Name: InstallWaptserver; Description: "{cm:InstallWaptServer}"; GroupDescription: "WAPTServer"
#endif

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

en.RegisteringService=Setup WaptServer Service
en.InstallMSVC2013=Installing MSVC++ 2013 Redistribuable
en.LaunchingPostconf=Launch server post-configuration
en.InstallNGINX=Install NGINX http server(will use ports 80 and 443)
en.InstallPostgreSQL=Install PostgreSQL Server
en.InstallWaptServer=Install Wapt server
en.ScanPackages=Scan packages
en.InstallingServerServices=Installing Server services...

de.RegisteringService=Setup WaptServer Service
de.InstallMSVC2013=MSVC++ 2013 Redistribuable installieren
de.LaunchingPostconf=Server Post-Konfiguration starten
de.InstallNGINX=NGINX installieren http Server
de.InstallPostgreSQL=PostgreSQL Server installieren
en.InstallWaptServer=Wapt server installieren


[InstallDelete]
Type: files; Name: "{app}\waptserver\waptserver.py*"

[Files]
Source: "..\waptsetuputil.dll"; Flags: dontcopy

[Code]
var
    labServerPassword,labServerPassword2: TLabel;
    edServerPassword,edServerPassword2: TEdit;
    

procedure waptsetuputil_init( language : integer );                     external 'waptsetuputil_init@files:waptsetuputil.dll stdcall';
function  waptsetuputil_validate_wapt_server_install_ports() : boolean; external 'waptsetuputil_validate_wapt_server_install_ports@files:waptsetuputil.dll stdcall';
function  SSLLeay_version( _type  : integer ) : Cardinal;               external 'SSLeay_version@files:libeay32.dll cdecl';
function  SSL_library_init() : integer;                                 external 'SSL_library_init@files:ssleay32.dll cdecl'; 

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

function NextButtonClick(CurPageID: Integer):Boolean;
var
  b : boolean; 
  s : String;
  r : integer;
begin
  result := true;

  if wpWelcome = CurPageID then
  begin
    s := ExpandConstant('{language}');
    if 'fr' = s then
      r := 2
    else if 'de' = s then
      r := 3
    else
      r := 1;  
    waptsetuputil_init( r );
    exit;
  end;

  if CurPageID = CustomPage.Id then
  begin
    if edServerPassword.text = edServerPassword2.text then
    begin
      Result := True;
      Exit;
    end
    else
    begin
      MsgBox('Check both password', mbError, MB_ABORTRETRYIGNORE);
      Result := False;
      Exit;
    end;
  end;


  if CurPageID = wpSelectTasks then
  begin
    result := waptsetuputil_validate_wapt_server_install_ports();
    exit;
  end;

end;

function GetServerPassword(Param: String):String;
begin
  if (edServerPassword.Text<>'') and (edServerPassword.Text = edServerPassword2.Text) then
    Result := Encode64(edServerPassword.Text)
  else
    Result := Encode64('')
end;

procedure InitializeWizard;
begin
  CustomPage := CreateCustomPage(wpSelectTasks, 'Server options', '');
  
  labServerPassword := TLabel.Create(WizardForm);
  labServerPassword.Parent := CustomPage.Surface; 
  labServerPassword.Caption := 'WAPT Server Admin password (leave blank to not change password):';

  edServerPassword := TEdit.Create(WizardForm);
  edServerPassword.PasswordChar := '*';
  edServerPassword.Parent := CustomPage.Surface; 
  edServerPassword.Left := labServerPassword.Left + labServerPassword.Width + 5;
  edServerPassword.Width := CustomPage.SurfaceWidth - labServerPassword.Width;
  edServerPassword.Top := labServerPassword.Top;
  edServerPassword.text := '';
  
  labServerPassword2 := TLabel.Create(WizardForm);
  labServerPassword2.Parent := CustomPage.Surface; 
  labServerPassword2.Caption := 'Confirm password:';
  labServerPassword2.Top := edServerPassword.Top + edServerPassword.Height + 5;

  edServerPassword2 := TEdit.Create(WizardForm);
  edServerPassword2.PasswordChar := '*';
  edServerPassword2.Parent := CustomPage.Surface; 
  edServerPassword2.Left := edServerPassword.Left;
  edServerPassword2.Width := edServerPassword.Width;
  edServerPassword2.Top := labServerPassword2.Top;
  edServerPassword2.text := '';
end;


