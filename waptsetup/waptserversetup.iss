#define waptserver
#define edition "waptserversetup"
#define AppName "WAPT Server"
#define default_repo_url "http://127.0.0.1/wapt/"
#define default_wapt_server "http://127.0.0.1"
#define default_wapt_password "mywapt"
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

#define vcredist

;#define signtool "kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f"

#ifndef set_disable_hiberboot
#define set_disable_hiberboot ""
#endif

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
Source: "..\waptserverpostconf.manifest"; DestDir: "{app}";

; deployment/upgrade tool
Source: "..\waptdeploy.exe"; DestDir: "{app}\waptserver\repository\wapt\"; Flags: ignoreversion

Source: "..\runwaptservice.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\runwaptserver.bat"; DestDir: "{app}"; Flags: ignoreversion

#ifdef choose_components
Source: "..\waptserver\waptserver.ini.template"; DestDir: "{app}\conf"; DestName: "waptserver.ini"; Tasks: InstallWaptserver
Source: "..\waptserver\*.py"; DestDir: "{app}\waptserver"; Tasks: InstallWaptserver       
Source: "..\waptserver\*.bat"; DestDir: "{app}\waptserver"; Tasks: InstallWaptserver       
Source: "..\waptserver\*.template"; DestDir: "{app}\waptserver"; Tasks: InstallWaptserver
Source: "..\waptserver\templates\*"; DestDir: "{app}\waptserver\templates"; Flags: createallsubdirs recursesubdirs; Tasks: InstallWaptserver
Source: "..\waptserver\translations\*"; DestDir: "{app}\waptserver\translations"; Flags: createallsubdirs recursesubdirs; Tasks: InstallWaptserver
Source: "..\waptserver\scripts\*"; DestDir: "{app}\waptserver\scripts"; Flags: createallsubdirs recursesubdirs; Tasks: InstallWaptserver
Source: "..\waptserver\pgsql\*"; DestDir: "{app}\waptserver\pgsql"; Flags: createallsubdirs recursesubdirs; Tasks: InstallPostgreSQL
Source: "..\waptserver\nginx\*"; DestDir: "{app}\waptserver\nginx"; Flags: createallsubdirs recursesubdirs; Tasks: InstallNGINX
Source: "..\waptserver\mongodb\mongoexport.exe"; DestDir: "{app}\waptserver\mongodb"; Check: DirExists(ExpandConstant('{app}\waptserver\mongodb'));  Tasks: InstallWaptserver

; waptenterprise only
#ifdef waptenterprise
Source: "..\waptenterprise\waptserver\*"; DestDir: "{app}\waptenterprise\waptserver\";  Flags: createallsubdirs recursesubdirs;Tasks: InstallWaptserver
#endif

#else
Source: "..\waptserver\waptserver.ini.template"; DestDir: "{app}\conf"; DestName: "waptserver.ini"; 
Source: "..\waptserver\*.py"; DestDir: "{app}\waptserver";   
Source: "..\waptserver\*.bat"; DestDir: "{app}\waptserver";   
Source: "..\waptserver\*.template"; DestDir: "{app}\waptserver"; 
Source: "..\waptserver\templates\*"; DestDir: "{app}\waptserver\templates"; Flags: createallsubdirs recursesubdirs;
Source: "..\waptserver\translations\*"; DestDir: "{app}\waptserver\translations"; Flags: createallsubdirs recursesubdirs; 
Source: "..\waptserver\scripts\*"; DestDir: "{app}\waptserver\scripts"; Flags: createallsubdirs recursesubdirs;
Source: "..\waptserver\pgsql\*"; DestDir: "{app}\waptserver\pgsql"; Flags: createallsubdirs recursesubdirs;
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

[INI]
Filename: {app}\conf\waptserver.ini; Section: options; Key: allow_unauthenticated_registration; String: True;


[RUN]
Filename: "{app}\waptserver\pgsql\vcredist_x64.exe"; Parameters: "/passive /quiet"; StatusMsg: {cm:InstallMSVC2013}; Description: "{cm:InstallMSVC2013}";  
Filename: "{app}\wapt-get.exe"; Parameters: " update-packages {app}\waptserver\repository\wapt"; StatusMsg: {cm:ScanPackages}; Description: "{cm:ScanPackages}"
Filename: "{app}\waptpython.exe"; Parameters: "{app}\waptserver\winsetup.py all -c {app}\conf\waptserver.ini -f --setpassword={#default_wapt_password}"; StatusMsg: {cm:ScanPackages}; Description: "{cm:InstallingServerServices}"
Filename: "net"; Parameters: "start waptpostgresql"; Flags: runhidden; StatusMsg: "Starting service waptpostgresql"
Filename: "net"; Parameters: "start waptnginx"; Flags: runhidden; StatusMsg: "Starting service waptnginx"
Filename: "net"; Parameters: "start waptserver"; Flags: runhidden; StatusMsg: "Starting service waptserver"
#ifdef waptenterprise
Filename: "net"; Parameters: "start wapttasks"; Flags: runhidden; StatusMsg: "Starting service wapttasks"
#endif
Filename: "{app}\waptserverpostconf.exe"; Flags: postinstall runascurrentuser skipifsilent shellexec; StatusMsg: {cm:RunConfigTool}; Description: "{cm:RunConfigTool}"

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

[Code]
function NextButtonClick(CurPageID: Integer):Boolean;
var
  Reply: Integer;
  NetstatOutput, ConflictingService: AnsiString;
begin


  if CurPageID <> wpSelectTasks then
  begin
    Result := True;
    Exit;
  end;

  ConflictingService := '';

  NetstatOutput := RunCmd('netstat -a -n -p tcp', True);
  if Pos('0.0.0.0:443 ', NetstatOutput) > 0 then
    ConflictingService := '443'
  else if Pos('0.0.0.0:80 ', NetstatOutput) > 0 then
    ConflictingService := '80'
  ;

  if ConflictingService = '' then
  begin
    Result := True;
    Exit;
  end;

  Reply := MsgBox('There already is a Web server listening on port '+ ConflictingService +'. ' +
   'You have several choices: abort the installation, ignore this warning (NOT RECOMMENDED), ' +
   'deactivate the conflicting service and replace it with our bundled Apache server, or choose ' +
   'not to install Apache.  In the latter case it is advised to set up your Web server as a reverse ' +
   'proxy to http://localhost:8080/.' , mbError, MB_ABORTRETRYIGNORE);
  if Reply = IDABORT then
    Abort;

  Result := Reply = IDIGNORE;

end;

procedure InitializeWizard;
begin
end;


