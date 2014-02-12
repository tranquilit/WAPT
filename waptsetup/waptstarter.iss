#define waptstarter 
#define default_repo_url "http://wapt.tranquil.it/wapt"
#define default_update_period "120"
#define default_update_maxruntime "30"
#define AppName "WaptStarter"
#include "wapt.iss"



[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {#default_repo_url};

[Setup]

DefaultDirName={pf}\wapt
OutputBaseFilename=waptstarter

