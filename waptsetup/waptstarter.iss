#define waptsetup 
#define default_repo_url "http://wapt.tranquil.it/wapt"
#define default_wapt_server ""
#define default_update_period "120"
#define AppName "WaptStarter"
#define output_dir "."
#define Company "Tranquil IT Systems"
#define signtool "kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f"

#include "wapt.iss"

[Files]
; sources of installer to rebuild a custom installer
Source: "innosetup\*"; DestDir: "{app}\waptsetup\innosetup";
Source: "wapt.iss"; DestDir: "{app}\waptsetup";
Source: "waptsetup.iss"; DestDir: "{app}\waptsetup";
Source: "services.iss"; DestDir: "{app}\waptsetup";
Source: "..\wapt.ico"; DestDir: "{app}";

[Setup]
OutputBaseFilename=waptstarter
DefaultDirName={pf}\wapt
WizardImageFile=..\tranquilit.bmp


;[Tasks]
;Name: use_hostpackages; Description: "Use automatic host management based on hostname packages"; Flags: unchecked;

[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {#default_repo_url};
Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: "0"
;Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: "1"; Tasks: use_hostpackages;
;Filename: {app}\wapt-get.ini; Section: global; Key: use_hostpackages; String: "0"; Tasks: not use_hostpackages;

[Icons]
Name: "{commonprograms}\WaptStarter"; IconFilename: "{app}\wapt.ico"; Filename: "http://localhost:8088";
Name: "{commondesktop}\WaptStarter"; IconFilename: "{app}\wapt.ico"; Filename: "http://localhost:8088";

[Run]
Filename: "{app}\wapt-get.exe"; Parameters: "--direct update"; Flags: runhidden; StatusMsg: "Mise à jour des paquets disponibles sur le dépôt principal"; Description: "Mise à jour des paquets disponibles sur le dépôt principal"
Filename: "{app}\wapt-get.exe"; Parameters: "add-upgrade-shutdown"; Tasks: autoUpgradePolicy; Flags: runhidden; StatusMsg: "Mise à jour des paquets à l'extinction du poste"; Description: "Mise à jour des paquets à l'extinction du poste"


[Code]
procedure DeinitializeUninstall();
var
    installdir: String;
begin
    installdir := ExpandConstant('{app}');
    if DirExists(installdir) and 
       (MsgBox('Des fichiers restent présents dans votre répertoire ' + installdir + ', souhaitez-vous le supprimer ainsi que tous les fichiers qu''il contient ?',
               mbConfirmation, MB_YESNO) = IDYES) then
        Deltree(installdir, True, True, True);
end;
