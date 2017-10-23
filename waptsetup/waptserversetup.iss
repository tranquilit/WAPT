#ifndef edition

#define edition "waptserversetup"
#define AppName "WAPT Server"
#define default_repo_url "http://localhost:8080/wapt/"
#define default_wapt_server "http://localhost:8080"

#define repo_url ""
#define wapt_server ""

#define output_dir "."
#define Company "Tranquil IT Systems"

#define send_usage_report "1"

#define is_waptagent "0"

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

;#define signtool "kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f"

; for fast compile in developent mode
#define FastDebug
#endif

#include "wapt.iss"

[Files]

; server postconf utility
Source: "..\waptserverpostconf.exe"; DestDir: "{app}"; Flags: ignoreversion; Tasks: InstallWaptserver

; deployment/upgrade tool
Source: "..\waptdeploy.exe"; DestDir: "{app}\waptserver\repository\wapt\"; Flags: ignoreversion

; Sources for server application
;Source: "waptserver.iss"; DestDir: "{app}\waptsetup"; Tasks: InstallWaptserver
Source: "..\waptserver\waptserver.ini.template"; DestDir: "{app}\conf"; DestName: "waptserver.ini"; Tasks: InstallWaptserver
Source: "..\waptserver\*.py"; DestDir: "{app}\waptserver"; Tasks: InstallWaptserver       
Source: "..\waptserver\*.template"; DestDir: "{app}\waptserver"; Tasks: InstallWaptserver
Source: "..\waptserver\templates\*"; DestDir: "{app}\waptserver\templates"; Flags: createallsubdirs recursesubdirs; Tasks: InstallWaptserver
Source: "..\waptserver\translations\*"; DestDir: "{app}\waptserver\translations"; Flags: createallsubdirs recursesubdirs; Tasks: InstallWaptserver
Source: "..\waptserver\scripts\*"; DestDir: "{app}\waptserver\scripts"; Flags: createallsubdirs recursesubdirs; Tasks: InstallWaptserver
Source: "..\waptserver\pgsql\*"; DestDir: "{app}\waptserver\pgsql"; Flags: createallsubdirs recursesubdirs; Tasks: InstallPostgreSQL
Source: "..\waptserver\nginx\*"; DestDir: "{app}\waptserver\nginx"; Flags: createallsubdirs recursesubdirs; Tasks: InstallNGINX

;#ifndef FastDebug
;#endif

; For UninstallRun
Source: "..\waptserver\uninstall-services.bat"; Destdir: "{app}\waptserver\"

[Setup]
OutputBaseFilename={#edition}
DefaultDirName=c:\wapt
WizardImageFile=..\tranquilit.bmp
DisableProgramGroupPage=yes

[Languages]
Name:"en"; MessagesFile: "compiler:Default.isl"
Name:"fr";MessagesFile: "compiler:Languages\French.isl"
Name:"de";MessagesFile: "compiler:Languages\German.isl"

[Dirs]
Name: "{app}\waptserver\repository"
Name: "{app}\waptserver\log"
Name: "{app}\waptserver\repository\wapt"
Name: "{app}\waptserver\repository\wapt-host"
Name: "{app}\waptserver\repository\wapt-group"
Name: "{app}\waptserver\nginx\ssl"

[RUN]
Filename: "{app}\waptpythonw.exe"; Parameters: """{app}\waptserver\waptserver_winsetup.py""  {code:GetWaptServerInstallFlags}"; StatusMsg: {cm:RegisteringService}; Description: "{cm:RegisteringService}"; Tasks: InstallWaptserver;
Filename: "{app}\waptpythonw.exe"; Parameters: """{app}\waptserver\waptserver_winsetup.py""  {code:GetWaptServerInstallFlags}"; StatusMsg: {cm:RegisteringService}; Description: "{cm:RegisteringService}"; Tasks: InstallPostgreSQL; 
Filename: "{app}\waptpythonw.exe"; Parameters: """{app}\waptserver\waptserver_winsetup.py""  {code:GetWaptServerInstallFlags}"; StatusMsg: {cm:RegisteringService}; Description: "{cm:RegisteringService}"; Tasks: InstallNGINX;
Filename: "{app}\waptserverpostconf.exe"; Parameters: "-l {code:CurrentLanguage}"; Flags: nowait postinstall runascurrentuser skipifsilent; StatusMsg: {cm:LaunchingPostconf}; Description: "{cm:LaunchingPostconf}"

[Tasks]
Name: InstallNGINX; Description: "{cm:InstallNGINX}"; GroupDescription: "WAPTServer"
Name: InstallPostgreSQL; Description: "{cm:InstallPostgreSQL}"; GroupDescription: "WAPTServer"
Name: InstallWaptserver; Description: "{cm:InstallWaptServer}"; GroupDescription: "WAPTServer"

[UninstallRun]
Filename: "{app}\waptserver\uninstall-services.bat"; Flags: runhidden; StatusMsg: "Stopping and deregistering waptserver"

[CustomMessages]
fr.RegisteringService=Mise en place du service WaptServer
fr.LaunchingPostconf=Lancement de la post-configuration du serveur
fr.InstallNGINX=Installer le serveur http NGINX (utlise les ports 80 et 443)
fr.InstallPostgreSQL=Installer le serveur PostgreSQL
fr.InstallWaptServer=Installer le serveur Wapt

en.RegisteringService=Setup WaptServer Service
en.LaunchingPostconf=Launch server post-configuration
en.InstallNGINX=Install NGINX http server(will use ports 80 and 443)
en.InstallPostgreSQL=Install PostgreSQL Server
en.InstallWaptServer=Install Wapt server

de.RegisteringService=Setup WaptServer Service
de.LaunchingPostconf=Server Post-Konfiguration starten
de.InstallNGINX=NGINX installieren http Server
de.InstallPostgreSQL=PostgreSQL Server installieren
en.InstallWaptServer=Wapt server installieren

[Code]

function GetWaptServerInstallFlags(Param: String):String;
begin
  Result := '';
  if not IsTaskSelected('InstallNGINX') then
    Result := Result +' --without-nginx';
  if not IsTaskSelected('InstallPostgreSQL') then
    Result := Result +' --without-postgresql';
end;

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

  if not IsTaskSelected('installApache') then
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

