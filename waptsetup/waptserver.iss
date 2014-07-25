#define waptserver 
#define AppName "WAPT Server"
#define default_repo_url "http://localhost:8080/wapt/"
#define default_wapt_server "http://localhost:8080"
#define default_update_period "120"
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
Source: "..\waptconsole.exe"; DestDir: "{app}";
Source: "..\waptdevutils.py"; DestDir: "{app}";

; server postconf utility
Source: "..\waptserverpostconf.exe"; DestDir: "{app}";

; pymongo
Source: "..\lib\site-packages\pymongo\*"; DestDir: "{app}\lib\site-packages\pymongo"; Flags: createallsubdirs recursesubdirs ; Excludes: "*.pyc,test,*.~*,*.chm,testsuite,Demos,test,HTML"

; Sources for server application
Source: "waptserver.iss"; DestDir: "{app}\waptsetup";
Source: "..\waptserver\waptserver.ini.template"; DestDir: "{app}\waptserver"; DestName: "waptserver.ini"
Source: "..\waptserver\*.py"; DestDir: "{app}\waptserver";       
Source: "..\waptserver\*.template"; DestDir: "{app}\waptserver";  
Source: "..\waptserver\templates\*"; DestDir: "{app}\waptserver\templates"; Flags: createallsubdirs recursesubdirs
Source: "..\waptserver\scripts\*"; DestDir: "{app}\waptserver\scripts"; Flags: createallsubdirs recursesubdirs
Source: "..\waptserver\mongodb\mongod.*"; DestDir: "{app}\waptserver\mongodb"; Flags: createallsubdirs recursesubdirs
Source: "..\waptserver\apache-win32\*"; DestDir: "{app}\waptserver\apache-win32"; Flags: createallsubdirs recursesubdirs

[Dirs]
Name: "{app}\waptserver\repository"
Name: "{app}\waptserver\log"
Name: "{app}\waptserver\repository\wapt"
Name: "{app}\waptserver\repository\wapt-host"
Name: "{app}\waptserver\repository\wapt-group"
Name: "{app}\waptserver\mongodb\data"
Name: "{app}\waptserver\mongodb\log"


[Setup]
OutputBaseFilename=waptserversetup
DefaultDirName="C:\wapt"
WizardImageFile=..\tranquilit.bmp

[INI]
;Filename: {app}\wapt-get.ini; Section: global; Key: wapt_server; String: {code:GetWaptServerURL};
;Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {code:GetRepoURL};
Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: "1";

[RUN]
Filename: "{app}\wapt-get.exe"; Parameters: "add-upgrade-shutdown"; Tasks: autoUpgradePolicy; Flags: runhidden; StatusMsg: "Mise à jour des paquets à l'extinction du poste"; Description: "Mise à jour des paquets à l'extinction du poste"
Filename: "{app}\waptpython.exe"; Parameters: """{app}\waptserver\waptserver.py"" install"; StatusMsg: "Registering WaptServer Service"    ; Description: "Setup WaptServer Service"
Filename: "net"; Parameters: "start waptmongodb"; StatusMsg: "Starting WaptMongodb service"
Filename: "{app}\waptserverpostconf.exe"; Flags: nowait postinstall skipifsilent; StatusMsg: "Lancement de la post-configuration du serveur"; Description: "Lancement de la post-configuration du serveur"

[Icons]
Name: "{commonstartup}\WAPT session setup"; Tasks: autorunSessionSetup; Filename: "{app}\wapt-get.exe"; Parameters: "session-setup ALL"; Flags: runminimized excludefromshowinnewinstall;
Name: "{commonstartup}\WAPT tray helper"; Tasks: autorunTray; Filename: "{app}\wapttray.exe"; Flags: excludefromshowinnewinstall;
Name: "{group}\Console WAPT"; Filename: "{app}\waptconsole.exe"; WorkingDir: "{app}"
Name: "{group}\Logiciels installés avec WAPT"; Filename: "http://localhost:8088/status"

[Tasks]
Name: autorunSessionSetup; Description: "Lancer WAPT session setup à l'ouverture de session";

[UninstallRun]
Filename: "net"; Parameters: "stop waptmongodb /yes"; Flags: runhidden; StatusMsg: "Stop WAPTMongodb"
Filename: "sc"; Parameters: "delete waptmongob"; Flags: runhidden; StatusMsg: "Unregister WAPTMongodb"
Filename: "net"; Parameters: "stop waptapache /yes"; Flags: runhidden; StatusMsg: "Stop WAPTApache"
Filename: "sc"; Parameters: "delete waptapache"; Flags: runhidden; StatusMsg: "Unregister WAPTApache"
Filename: "net"; Parameters: "stop waptserver"; Flags: runhidden; StatusMsg: "Stop WAPTServer"
Filename: "sc"; Parameters: "delete waptserver"; Flags: runhidden; StatusMsg: "Unregister WAPTServer"
