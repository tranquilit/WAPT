#define waptstarter 
#define default_repo_url "http://wapt.tranquil.it/wapt"
#define default_update_period "120"
#define default_update_maxruntime "30"
#define AppName "WaptStarter"

#define output_dir "."
#define Company "Tranquil IT Systems"
#define signtool "kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f"

#include "wapt.iss"

[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {#default_repo_url};

[Setup]
DefaultDirName={pf}\wapt
OutputBaseFilename=waptstarter

[Run]
Filename: "{app}\waptpython.exe"; Parameters: "{app}\waptservice\waptservice.py install"; Flags: runhidden; StatusMsg: "Install waptservice"; Description: "Install waptservice"
Filename: "{app}\wapt-get.exe"; Parameters: "register"; Flags: runhidden postinstall; StatusMsg: "Register computer on the WAPT server"; Description: "Register computer on the WAPT server"
Filename: "{app}\wapttray.exe"; Tasks: autorunTray; Flags: runminimized nowait runasoriginaluser postinstall; StatusMsg: "Launch WAPT tray icon"; Description: "Launch WAPT tray icon"

