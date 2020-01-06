#define SrcApp wapt_base_dir+"wapt-get.exe"
#define FileVerStr GetFileVersion(SrcApp)
#define AppVerStr FileVerStr

; offer the install of vcredist.exe
;#define vcredist
#define msvcrt90

#ifndef FastDebug
[Files]
; local python interpreter
Source: "{#wapt_base_dir}waptpython.exe"; DestDir: "{app}";
Source: "{#wapt_base_dir}waptpythonw.exe"; DestDir: "{app}";
Source: "{#wapt_base_dir}waptpython.exe"; DestDir: "{app}\Scripts"; DestName: "python.exe"
Source: "{#wapt_base_dir}waptpythonw.exe"; DestDir: "{app}\Scripts"; DestName: "pythonw.exe"
Source: "{#wapt_base_dir}DLLs\*"; DestDir: "{app}\DLLs"; Flags: createallsubdirs recursesubdirs
Source: "{#wapt_base_dir}libs\*"; DestDir: "{app}\libs"; Flags: createallsubdirs recursesubdirs  ; Excludes: "*.pyc,*.pyo,test,*.~*,pydoc_data,tests,demos,testsuite,doc,samples,pil" 
Source: "{#wapt_base_dir}python27.dll"; DestDir: "{app}";
Source: "{#wapt_base_dir}pythoncom27.dll"; DestDir: "{app}";
Source: "{#wapt_base_dir}pythoncomloader27.dll"; DestDir: "{app}";
Source: "{#wapt_base_dir}pywintypes27.dll"; DestDir: "{app}";
;Source: "{#wapt_base_dir}sqlite3.dll"; DestDir: "{app}"; 

Source: "{#wapt_base_dir}Scripts\*"; DestDir: "{app}\Scripts"; Flags: createallsubdirs recursesubdirs ;

; additional python modules
Source: "{#wapt_base_dir}lib\*"; DestDir: "{app}\lib"; Flags: createallsubdirs recursesubdirs ; Excludes: "*.dist-info,*.pyc,*.pyo,test,*.~*,bson,*.chm,testsuite,Demos,tests,examples,HTML,scintilla,idle,idlelib,pylint,isort,mccabe*,*.whl,pydoc_data"

; workaround for Windows XP openssl
Source: "{app}\lib\site-packages\cryptography\hazmat\bindings242\*"; DestDir: "{app}\lib\site-packages\cryptography\hazmat\bindings"; OnlyBelowVersion: 6.0; Flags: external createallsubdirs recursesubdirs ; 

; wapt sources
Source: "{#wapt_base_dir}waptutils.py"; DestDir: "{app}"; 
Source: "{#wapt_base_dir}waptcrypto.py"; DestDir: "{app}"; 
Source: "{#wapt_base_dir}common.py"; DestDir: "{app}"; 
Source: "{#wapt_base_dir}waptpackage.py"; DestDir: "{app}"; 
Source: "{#wapt_base_dir}wapt-get.py"; DestDir: "{app}"; 
Source: "{#wapt_base_dir}keyfinder.py"; DestDir: "{app}"; 
Source: "{#wapt_base_dir}setuphelpers.py"; DestDir: "{app}"; 
Source: "{#wapt_base_dir}setuphelpers_windows.py"; DestDir: "{app}"; 
Source: "{#wapt_base_dir}setuphelpers_linux.py"; DestDir: "{app}"; 
Source: "{#wapt_base_dir}windnsquery.py"; DestDir: "{app}"; 
Source: "{#wapt_base_dir}custom_zip.py"; DestDir: "{app}"; 
#ifdef waptenterprise
Source: "{#wapt_base_dir}waptenterprise\COPYING.txt"; DestDir: "{app}";
Source: "{#wapt_base_dir}waptenterprise\COPYING.txt"; DestDir: "{app}\waptenterprise";
Source: "{#wapt_base_dir}wapt-enterprise.ico"; DestDir: "{app}";
#else
Source: "{#wapt_base_dir}COPYING.txt"; DestDir: "{app}";
#endif
Source: "{#wapt_base_dir}version"; DestDir: "{app}";
Source: "{#wapt_base_dir}revision.txt"; DestDir: "{app}";
Source: "{#wapt_base_dir}templates\*"; DestDir: "{app}\templates"; Flags: createallsubdirs recursesubdirs

; for openssl get dll in path
Source: "{#wapt_base_dir}libeay32.dll" ; DestDir: "{app}"; 
Source: "{#wapt_base_dir}ssleay32.dll" ; DestDir: "{app}";
Source: "{#wapt_base_dir}openssl.exe" ; DestDir: "{app}";

; for local waptservice
Source: "{#wapt_base_dir}waptservice\win32\*"; DestDir: "{app}\waptservice\win32\";  Flags: createallsubdirs recursesubdirs;
Source: "{#wapt_base_dir}waptservice\win64\*"; DestDir: "{app}\waptservice\win64\";  Flags: createallsubdirs recursesubdirs;
Source: "{#wapt_base_dir}waptservice\*.py"; DestDir: "{app}\waptservice\"; 
Source: "{#wapt_base_dir}waptservice\static\*"; DestDir: "{app}\waptservice\static"; Flags: createallsubdirs recursesubdirs; Tasks: 
Source: "{#wapt_base_dir}waptservice\ssl\*"; DestDir: "{app}\waptservice\ssl"; Flags: createallsubdirs recursesubdirs;
Source: "{#wapt_base_dir}waptservice\templates\*"; DestDir: "{app}\waptservice\templates"; Flags: createallsubdirs recursesubdirs; 
Source: "{#wapt_base_dir}waptservice\translations\*"; DestDir: "{app}\waptservice\translations"; Flags: createallsubdirs recursesubdirs; 
Source: "{#wapt_base_dir}waptservice\plugins\*"; DestDir: "{app}\waptservice\plugins"; Flags: createallsubdirs recursesubdirs; 

; waptenterprise only
#ifdef waptenterprise
Source: "{#wapt_base_dir}waptenterprise\waptservice\*"; DestDir: "{app}\waptenterprise\waptservice\";  Flags: createallsubdirs recursesubdirs;
Source: "{#wapt_base_dir}waptenterprise\waptconsole\*"; DestDir: "{app}\waptenterprise\waptconsole\";  Flags: createallsubdirs recursesubdirs;
Source: "{#wapt_base_dir}waptenterprise\waptwua\*"; DestDir: "{app}\waptenterprise\waptwua\";  Flags: createallsubdirs recursesubdirs;
Source: "{#wapt_base_dir}waptenterprise\__init__.py"; DestDir: "{app}\waptenterprise\";
Source: "{#wapt_base_dir}waptenterprise\licencing.py"; DestDir: "{app}\waptenterprise\";
Source: "{#wapt_base_dir}waptenterprise\enterprise_common.py"; DestDir: "{app}\waptenterprise\";
#endif


; user feedback of waptservice activity
Source: "{#wapt_base_dir}wapttray.exe"; DestDir: "{app}"; BeforeInstall: killtask('wapttray.exe'); Flags: ignoreversion 

; command line tools
Source: "{#wapt_base_dir}wapt-scanpackages.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#wapt_base_dir}wapt-scanpackages.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#wapt_base_dir}wapt-signpackages.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#wapt_base_dir}wapt-signpackages.py"; DestDir: "{app}"; Flags: ignoreversion

Source: "{#wapt_base_dir}runwaptservice.bat"; DestDir: "{app}"; Flags: ignoreversion

Source: "{#wapt_base_dir}wapt-get.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#wapt_base_dir}waptguihelper.pyd"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#wapt_base_dir}wapt-get.exe.manifest"; DestDir: "{app}";
Source: "{#wapt_base_dir}dmidecode.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#wapt_base_dir}waptexit.exe"; DestDir: "{app}"; Flags: ignoreversion

; for local debugging and pyscripter
Source: "{#wapt_base_dir}wapt.psproj"; DestDir: "{app}"; 
Source: "{#wapt_base_dir}devwapt.bat"; DestDir: "{app}"; 
Source: "{#wapt_base_dir}waptpyscripter.bat"; DestDir: "{app}"; 

; deployment/upgrade tool
Source: "{#wapt_base_dir}waptdeploy.exe"; DestDir: "{app}"; Flags: ignoreversion restartreplace; 

; translations
Source: "{#wapt_base_dir}languages\*"; DestDir: "{app}\languages\"; Flags: createallsubdirs recursesubdirs;

; local package cache
Source: "{#wapt_base_dir}cache\icons\unknown.png"; DestDir: "{app}\cache\icons";

; for python : Visual C++ 2008 redistributable
#ifdef vcredist
Source: "{#wapt_base_dir}vc_redist\*"; DestDir: "{app}\vc_redist";
#endif
#ifdef msvcrt90
Source: "{#wapt_base_dir}msvc*90.dll"; DestDir: "{app}";
Source: "{#wapt_base_dir}Microsoft.VC90.CRT.manifest"; DestDir: "{app}";
#endif

; config file sample
Source: "{#wapt_base_dir}wapt-get.ini.tmpl"; DestDir: "{app}"; 

#endif

[Dirs]
Name: "{app}\ssl"
Name: "{app}\ssl\server"
Name: "{app}"; Permissions: everyone-readexec authusers-readexec admins-full   
Name: "{app}\private"
Name: "{app}\Scripts"
#ifdef waptenterprise
Name: "{app}\licences"
#endif

[Setup]
AppName={#AppName}
#ifdef AppId
AppId={#AppId}
#endif
AppVersion={#AppVerStr}
#ifdef waptenterprise
UninstallDisplayName={#AppName} Enterprise {#AppVerStr} 
#else
UninstallDisplayName={#AppName} Community {#AppVerStr} 
#endif
VersionInfoVersion={#FileVerStr}
VersionInfoTextVersion={#AppVerStr}
AppCopyright={#Company}
DefaultGroupName={#AppName}
ChangesEnvironment=True
AppPublisher={#Company}
OutputDir={#output_dir}
SolidCompression=True
AppPublisherURL=https://www.tranquil.it
AppUpdatesURL=https://wapt.tranquil.it/wapt/releases/latest
AppSupportURL=https://www.wapt.fr
AppContact=wapt@lists.tranquil.it
AppSupportPhone=+33 2 40 97 57 55
CloseApplications=Yes
RestartApplications=No
PrivilegesRequired=admin
MinVersion=0,5.0sp4

#ifdef waptenterprise
LicenseFile={#wapt_base_dir}waptenterprise\COPYING.txt
SetupIconFile={#wapt_base_dir}wapt-enterprise.ico
AppVerName={#AppName} Enterprise {#AppVerStr}
#else
LicenseFile={#wapt_base_dir}COPYING.txt
SetupIconFile={#wapt_base_dir}wapt.ico
AppVerName={#AppName} Community {#AppVerStr}
#endif
RestartIfNeededByRun=False


#ifdef signtool
SignTool={#signtool}
#endif

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}')
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wapt-get.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\wapt-get.exe"; Flags: uninsdeletekey

[Run]
#ifdef vcredist
Filename: "{app}\vc_redist\vcredist_x86.exe"; Parameters: "/q"; WorkingDir: "{tmp}"; StatusMsg: "{cm:InstallingVCpp}"; Description: "{cm:InstallingVCpp}"; Tasks: installredist2008
; Duplication necessaire, cf. [Tasks]
Filename: "{app}\vc_redist\vcredist_x86.exe"; Parameters: "/q"; WorkingDir: "{tmp}"; StatusMsg: "{cm:InstallingVCpp}"; Description: "{cm:InstallingVCpp}"; Tasks: installredist2008unchecked
#endif

; rights rw for Admins and System, ro for users and authenticated users on wapt directory
Filename: "cmd"; Parameters: "/C echo O| cacls ""{app}"" /S:""D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1201a9;;;AU)"""; Flags: runhidden; WorkingDir: "{tmp}"; StatusMsg: "{cm:SetupACL}"; Description: "{cm:SetupACL}";
Filename: "cmd"; Parameters: "/C icacls.exe ""{app}"" /inheritance:r"; MinVersion: 6.1; Flags: runhidden; WorkingDir: "{tmp}"; StatusMsg: "{cm:SetupACL}"; Description: "{cm:SetupACL}";
Filename: "cmd"; Parameters: "/C {app}\vc_redist\icacls.exe ""{app}"" /inheritance:r"; OnlyBelowVersion: 6.1; Flags: runhidden; WorkingDir: "{tmp}"; StatusMsg: "{cm:SetupACL}"; Description: "{cm:SetupACL}";

; protect waptagent private directory

Filename: "cmd"; Parameters: "/C icacls.exe ""{app}\private"" /inheritance:r  /grant *S-1-5-32-544:(OI)(CI)F  /grant *S-1-5-18:(OI)(CI)F"; MinVersion: 6.1; Flags: runhidden; WorkingDir: "{tmp}"; StatusMsg: "{cm:SetupACL}"; Description: "{cm:SetupACL}";

Filename: "cmd"; Parameters: "/C {app}\vc_redist\icacls.exe ""{app}\private"" /inheritance:r /grant *S-1-5-32-544:(OI)(CI)F  /grant *S-1-5-18:(OI)(CI)F"; OnlyBelowVersion: 6.1; Flags: runhidden; WorkingDir: "{tmp}"; StatusMsg: "{cm:SetupACL}"; Description: "{cm:SetupACL}";

; if waptservice
Filename: "{app}\waptpython.exe"; Parameters: """{app}\waptservice\service.py"" install"; Tasks:installService ; Flags: runhidden; StatusMsg: "{cm:InstallingWAPTservice}"; Description: "{cm:InstallingWAPTservice}";
Filename: "sc"; Parameters: "delete waptservice"; Flags: runhidden; Tasks: not installService; WorkingDir: "{tmp}"; StatusMsg: "{cm:UnregisterWaptService}"; Description: "Suppression du service wapt..."
Filename: "{app}\wapttray.exe"; Tasks: autorunTray; Flags: runminimized nowait runasoriginaluser skipifsilent postinstall; StatusMsg: "{cm:RunWaptTray}"; Description: "{cm:RunWaptTray}"; 



[Icons]
Name: "{commonstartup}\WAPT tray helper"; Tasks: autorunTray; Filename: "{app}\wapttray.exe"; Flags: excludefromshowinnewinstall;

[Tasks]
Name: installService; Description: "{cm:InstallWAPTservice}";  GroupDescription: "Base";
Name: autorunTray; Description: "{cm:LaunchIcon}"; Flags: unchecked;  GroupDescription: "Base";
#if edition == "waptstarter"
Name: EnableWaptServiceNoPassword; Description: "{cm:EnableWaptServiceNoPassword}";  GroupDescription: "Base";
#endif

#ifdef vcredist
Name: installredist2008; Description: "{cm:InstallVCpp}";  Check: VCRedistNeedsInstall();  GroupDescription: "Base";
; Duplication helas necessaire.
; On souhaite seulement changer les actions a realiser par defaut, pas a empecher
; l'utilisateur de forcer la reinstallation de VC++, et il n'existe pas de moyen
; de modifier dynamiquement le flag "unchecked" 
Name: installredist2008unchecked; Description: "{cm:ForceVCppReinstall}"; Check: not VCRedistNeedsInstall(); Flags: unchecked;  GroupDescription: "Base";
#endif

[InstallDelete]
#ifndef FastDebug
Type: filesandordirs; Name: "{app}\lib\site-packages"
#endif FastDebug
Type: files; Name: "{app}\*.pyc"
Type: files; Name: "{app}\waptservice\*.pyc"
Type: files; Name: "{app}\waptservice\waptservice.py*"

[UninstallRun]
Filename: "taskkill"; Parameters: "/t /im ""waptself.exe"" /f"; Flags: runhidden; StatusMsg: "Arrêt de waptself"
Filename: "taskkill"; Parameters: "/t /im ""waptconsole.exe"" /f"; Flags: runhidden; StatusMsg: "Arrêt de waptconsole"
Filename: "taskkill"; Parameters: "/t /im ""wapttray.exe"" /f"; Flags: runhidden; StatusMsg: "Arrêt de l'icône de notification"
Filename: "net"; Parameters: "stop waptservice"; Flags: runhidden; StatusMsg: "Arrêt du service WAPT"
Filename: "sc"; Parameters: "delete waptservice"; Flags: runhidden; StatusMsg: "Désinstallation du service WAPT"
Filename: "taskkill"; Parameters: "/t /im ""waptpython.exe"" /f"; Flags: runhidden; StatusMsg: "Arrêt de waptpython"

[CustomMessages]
;French translations here
fr.InstallWAPTservice=Installer le service WAPT
fr.InstallingWAPTservice=Installation du service WAPT...
fr.LaunchIcon=Lancer l'icône de notification lors de l'ouverture de session
fr.InstallVCpp=Installer les redistribuables VC++ 2008 (pour openssl)
fr.ForceVCppReinstall=Forcer la réinstallation des redistribuables VC++ 2008 (pour openssl)
fr.UpdatePkgUponShutdown=Proposer la mise à  jour des paquets à  l'extinction du poste
fr.LaunchSession=Lancer WAPT session setup à  l'ouverture de session
fr.InstallingVCpp=Installation des librairies MS VC++
fr.SetupACL=Mise en place des droits sur le répertoire wapt
fr.RunWaptTray=Lancement de l'icône de notification
fr.UnregisterWaptService=Suppression du service waptservice
fr.EnableWaptServiceNoPassword=Ne pas demander de mot de passe pour l'installation et la désinstallation des paquets Wapt.

;English translations here
en.InstallWAPTservice=Install WAPT service
en.InstallingWAPTservice=Installing WAPT service...
en.LaunchIcon=Launch notification icon upon session opening
en.InstallVCpp=Install VC++ 2008 redistributables (for openssl)
en.ForceVCppReinstall=Force-reinstall VC++ 2008 redistributables (for openssl)
en.UpdatePkgUponShutdown=Ask to update packages upon shutdown
en.LaunchSession=Launch WAPT setup session upon session opening
en.InstallingVCpp=Installing librairies MS VC++
en.SetupACL=Setup ACL rights on wapt directory
en.RunWaptTray=Launching notification tray icon
en.UnregisterWaptService=Removal of service waptservice
en.EnableWaptServiceNoPassword=Don't ask password for installation and removal of Wapt packages for local user

;German translations here
de.InstallWAPTservice=WAPT service installieren
de.LaunchIcon=Benachrichtigungssymbol bei Sitzungseröffnung  starten
de.InstallVCpp=VC++ 2008 die Redistributables (für openssl) installieren
de.ForceVCppReinstall=Force- VC++ 2008 redistributables (für openssl) deinstallieren
de.UpdatePkgUponShutdown=Bitten, die Packete beim herunterfahren zu aktualisieren
de.LaunchSession=WAPT setup Sitzung bei eröffnung der Sitzung starten


[Code]
#include "services.iss"
var
  edWaptRepoUrl:TEdit;

 
function RunCmd(cmd:AnsiString;RaiseOnError:Boolean):AnsiString;
var
  ErrorCode: Integer;
  TmpFileName, ExecStdout: Ansistring;
begin
  Result := 'Error';
  TmpFileName := ExpandConstant('{tmp}') + '\runresult.txt';
  try
    Exec('cmd','/C '+cmd+'  > "' + TmpFileName + '"', '', SW_HIDE,
      ewWaitUntilTerminated, ErrorCode);
    if RaiseOnError and (ErrorCode>0) then
       RaiseException('La commande '+cmd+' a renvoy le code d''erreur '+intToStr(ErrorCode));
    if LoadStringFromFile(TmpFileName, ExecStdout) then 
      result := ExecStdOut
    else 
      result:='';
  finally
    if FileExists(TmpFileName) then
	     DeleteFile(TmpFileName);
  end;
end;

// Usable even in the Uninstall section, contrary to WizardSilent
function runningSilently(): Boolean;
var
    i: Cardinal;
begin
    result := False; 
    for i := 1 to ParamCount do
    begin
        if ((CompareText(ParamStr(i), '/silent') = 0) or
            (CompareText(ParamStr(i), '/verysilent') = 0)) then
            result := True;
    end;
end;


procedure CurStepChanged(CurStep: TSetupStep);
var
  Reply, ResultCode: Integer;
  ServiceStatus: LongWord;
  NetstatOutput, ConflictingService: AnsiString;
begin
  if CurStep = ssInstall then
  begin
    // terminate waptconsole
    Exec('taskkill', '/t /im "waptconsole.exe" /f', '', SW_HIDE,
       ewWaitUntilTerminated, ResultCode);

    // Proceed Setup
    Exec('net', 'stop waptservice', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
   
  #ifdef waptserver

    Exec('net', 'stop wapttasks', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('net', 'stop waptserver', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('net', 'stop waptapache', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('net', 'stop waptnginx', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('net', 'stop waptmongodb', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('net', 'stop waptpostgresql', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd', '/c sc delete waptapache', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd', '/c sc delete waptmongodb', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  #endif

    Exec('taskkill', '/t /im "wapttray.exe" /f', '', SW_HIDE,
       ewWaitUntilTerminated, ResultCode);

    Exec('taskkill', '/t /im "waptexit.exe" /f', '', SW_HIDE,
       ewWaitUntilTerminated, ResultCode);

    // terminate additional waptpython
    Exec('taskkill', '/t /im "waptpython.exe" /f', '', SW_HIDE,
       ewWaitUntilTerminated, ResultCode);

    Exec('taskkill', '/t /im "pyscripter.exe" /f', '', SW_HIDE,
       ewWaitUntilTerminated, ResultCode);

    {
    repeat
      ConflictingService := '';

      NetstatOutput := RunCmd('netstat -a -n -p tcp', True);
      if Pos('TCP    127.0.0.1:8088 ', NetstatOutput) > 0 then
        ConflictingService := '8088'
  #ifdef waptserver
      else if Pos('TCP    127.0.0.1:8080 ', NetstatOutput) > 0 then
        ConflictingService := '8080'
  #endif
      ;

      if ConflictingService <> '' then
      begin
        if RunningSilently then
           Abort
        else
        begin
          Reply := MsgBox('A conflicting service is running on port '+ConflictingService+'. '+
                          'This is not supported and you should probably abort the installer. '+
                          'Visit http://dev.tranquil.it/ for documentation about WAPT.',
                          mbError, MB_ABORTRETRYIGNORE);
          if Reply = IDABORT then
            Abort;
        end;
      end;
    until (ConflictingService = '') or (Reply = IDIGNORE);}
  end
  else if CurStep = ssDone then
  begin
    if ServiceExists('waptservice') then
      SimpleStartService('waptservice',True,True);
  end;
end;

procedure killtask(name:String);
var
  errorcode:integer;
begin
  shellexec('','taskkill','/t /im "'+name+'" /f','',sw_Hide,ewWaitUntilTerminated,Errorcode);
end;

function NeedsAddPath(Param: String): boolean;
var
  OrigPath: string;
begin
  OrigPath := '';
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;

  OrigPath := ';'+OrigPath+';';
  Result := Pos(';' + UpperCase(ExpandConstant(Param)) + ';', UpperCase(OrigPath)) = 0;
  
end;


#ifdef vcredist 
// FROM: http://stackoverflow.com/questions/11137424/how-to-make-vcredist-x86-reinstall-only-if-not-yet-installed
#IFDEF UNICODE
#DEFINE AW "W"
#ELSE
#DEFINE AW "A"
#ENDIF
   type
      INSTALLSTATE =  Longint;
const
   INSTALLSTATE_INVALIDARG =  -2;  // An invalid parameter was passed to the function.
   INSTALLSTATE_UNKNOWN = -1;     // The product is neither advertised or installed.
   INSTALLSTATE_ADVERTISED = 1;   // The product is advertised but not installed.
   INSTALLSTATE_ABSENT = 2;       // The product is installed for a different user.
      INSTALLSTATE_DEFAULT = 5;      // The product is installed for the current user.

	 VC_2005_REDIST_X86 = '{A49F249F-0C91-497F-86DF-B2585E8E76B7}';
   VC_2005_REDIST_X64 = '{6E8E85E8-CE4B-4FF5-91F7-04999C9FAE6A}';
   VC_2005_REDIST_IA64 = '{03ED71EA-F531-4927-AABD-1C31BCE8E187}';
   VC_2005_SP1_REDIST_X86 = '{7299052B-02A4-4627-81F2-1818DA5D550D}';
   VC_2005_SP1_REDIST_X64 = '{071C9B48-7C32-4621-A0AC-3F809523288F}';
   VC_2005_SP1_REDIST_IA64 = '{0F8FB34E-675E-42ED-850B-29D98C2ECE08}';
   VC_2005_SP1_ATL_SEC_UPD_REDIST_X86 = '{837B34E3-7C30-493C-8F6A-2B0F04E2912C}';
   VC_2005_SP1_ATL_SEC_UPD_REDIST_X64 = '{6CE5BAE9-D3CA-4B99-891A-1DC6C118A5FC}';
   VC_2005_SP1_ATL_SEC_UPD_REDIST_IA64 = '{85025851-A784-46D8-950D-05CB3CA43A13}';

   VC_2008_REDIST_X86 = '{FF66E9F6-83E7-3A3E-AF14-8DE9A809A6A4}';
   VC_2008_REDIST_X64 = '{350AA351-21FA-3270-8B7A-835434E766AD}';
   VC_2008_REDIST_IA64 = '{2B547B43-DB50-3139-9EBE-37D419E0F5FA}';
   VC_2008_SP1_REDIST_X86 = '{9A25302D-30C0-39D9-BD6F-21E6EC160475}';
   VC_2008_SP1_REDIST_X64 = '{8220EEFE-38CD-377E-8595-13398D740ACE}';
   VC_2008_SP1_REDIST_IA64 = '{5827ECE1-AEB0-328E-B813-6FC68622C1F9}';
   VC_2008_SP1_ATL_SEC_UPD_REDIST_X86 = '{1F1C2DFC-2D24-3E06-BCB8-725134ADF989}';
   VC_2008_SP1_ATL_SEC_UPD_REDIST_X64 = '{4B6C7001-C7D6-3710-913E-5BC23FCE91E6}';
   VC_2008_SP1_ATL_SEC_UPD_REDIST_IA64 = '{977AD349-C2A8-39DD-9273-285C08987C7B}';
   VC_2008_SP1_MFC_SEC_UPD_REDIST_X86 = '{9BE518E6-ECC6-35A9-88E4-87755C07200F}';
   VC_2008_SP1_MFC_SEC_UPD_REDIST_X64 = '{5FCE6D76-F5DC-37AB-B2B8-22AB8CEDB1D4}';
   VC_2008_SP1_MFC_SEC_UPD_REDIST_IA64 = '{515643D1-4E9E-342F-A75A-D1F16448DC04}';

   VC_2010_REDIST_X86 = '{196BB40D-1578-3D01-B289-BEFC77A11A1E}';
   VC_2010_REDIST_X64 = '{DA5E371C-6333-3D8A-93A4-6FD5B20BCC6E}';
   VC_2010_REDIST_IA64 = '{C1A35166-4301-38E9-BA67-02823AD72A1B}';
   VC_2010_SP1_REDIST_X86 = '{F0C3E5D1-1ADE-321E-8167-68EF0DE699A5}';
   VC_2010_SP1_REDIST_X64 = '{1D8E6291-B0D5-35EC-8441-6616F567A0F7}';
   VC_2010_SP1_REDIST_IA64 = '{88C73C1C-2DE5-3B01-AFB8-B46EF4AB41CD}';

function MsiQueryProductState(szProduct :  string): INSTALLSTATE;
  external 'MsiQueryProductState{#AW}@msi.dll stdcall';

function VCVersionInstalled(const ProductID :  string): Boolean;
begin
  Result := MsiQueryProductState(ProductID) = INSTALLSTATE_DEFAULT;
end; { VCVersionInstalled }

function VCRedistNeedsInstall: Boolean;
begin
	      // here the Result must be True when you need to install your VCRedist
	      // or False when you don't need to, so now it's upon you how you build
	      // this statement, the following won't install your VC redist only when
  // the Visual C++ 2010 Redist (x86) and Visual C++ 2010 SP1 Redist(x86)
  // are installed for the current user


  // Note : on ne tient pas compte des versions plus anciennes de VC++ 2008
  Result := not VCVersionInstalled(VC_2008_SP1_MFC_SEC_UPD_REDIST_X86);
end;
#endif

function CurrentLanguage(Param: String):String;
var
  Current: String;
begin
  Result := 'en';
  Current := ActiveLanguage;
  // Whitelist
  if Current = 'fr' then
    Result := 'fr';
end;

