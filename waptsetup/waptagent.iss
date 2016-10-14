#define waptagent 
#define default_repo_url "http://wapt/wapt"
#define default_update_period "120"
#define default_update_maxruntime "30"
#define AppName "WaptAgent"
#include "wapt.iss"

[Files]
; authorized public keys
Source: "..\ssl\*"; DestDir: "{app}\ssl"; Flags: createallsubdirs recursesubdirs

[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {#default_repo_url};

[Setup]
DefaultDirName=c:\wapt
OutputBaseFilename=waptagent

