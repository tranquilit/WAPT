#define SrcApp AddBackslash(SourcePath) + "..\wapt-get.exe"
#define FileVerStr GetFileVersion(SrcApp)
#define StripBuild(str VerStr) Copy(VerStr, 1, RPos(".", VerStr)-1)
#define AppVerStr StripBuild(FileVerStr)

[Files]
; local python interpreter
Source: "..\waptpython.exe"; DestDir: "{app}";
Source: "..\DLLs\*"; DestDir: "{app}\DLLs"; Flags: createallsubdirs recursesubdirs
Source: "..\libs\*"; DestDir: "{app}\libs"; Flags: createallsubdirs recursesubdirs  ; Excludes: "*.pyc,test,*.~*,pydoc_data,tests,demos,testsuite,doc,samples,pil" 
Source: "..\Microsoft.VC90.CRT.manifest"; DestDir: "{app}";
Source: "..\msvcm90.dll"; DestDir: "{app}";
Source: "..\msvcp90.dll"; DestDir: "{app}";
Source: "..\msvcr90.dll"; DestDir: "{app}";
Source: "..\python27.dll"; DestDir: "{app}";
Source: "..\pythoncom27.dll"; DestDir: "{app}";
Source: "..\pythoncomloader27.dll"; DestDir: "{app}";
Source: "..\pywintypes27.dll"; DestDir: "{app}";
;Source: "..\sqlite3.dll"; DestDir: "{app}"; 

; additional python modules
Source: "..\lib\*"; DestDir: "{app}\lib"; Flags: createallsubdirs recursesubdirs ; Excludes: "*.pyc,test,*.~*,pymongo,*.chm,testsuite,Demos,test,HTML"

; wapt sources
Source: "..\common.py"; DestDir: "{app}"; 
Source: "..\waptpackage.py"; DestDir: "{app}"; 
Source: "..\wapt-get.py"; DestDir: "{app}"; 
Source: "..\keyfinder.py"; DestDir: "{app}"; 
Source: "..\setuphelpers.py"; DestDir: "{app}"; 
Source: "..\COPYING.txt"; DestDir: "{app}";
Source: "..\version"; DestDir: "{app}";
Source: "..\templates\*"; DestDir: "{app}\templates"; Flags: createallsubdirs recursesubdirs

; for openssl get dll in path
Source: "..\lib\site-packages\M2Crypto\libeay32.dll" ; DestDir: "{app}"; 
Source: "..\lib\site-packages\M2Crypto\ssleay32.dll" ; DestDir: "{app}";

; for local waptservice
Source: "..\libzmq.dll"; DestDir: "{app}";
Source: "..\waptservice\win32\*"; DestDir: "{app}\waptservice\win32\";  Flags: createallsubdirs recursesubdirs; Tasks: installService 
Source: "..\waptservice\win64\*"; DestDir: "{app}\waptservice\win64\";  Flags: createallsubdirs recursesubdirs; Tasks: installService
Source: "..\waptservice\waptservice*.py"; DestDir: "{app}\waptservice\"; Tasks: installService
Source: "..\waptservice\network_manager.py"; DestDir: "{app}\waptservice\"; Tasks: installService
Source: "..\waptservice\static\*"; DestDir: "{app}\waptservice\static"; Flags: createallsubdirs recursesubdirs; Tasks: installService 
Source: "..\waptservice\ssl\*"; DestDir: "{app}\waptservice\ssl"; Flags: createallsubdirs recursesubdirs; Tasks: installService 
Source: "..\waptservice\templates\*"; DestDir: "{app}\waptservice\templates"; Flags: createallsubdirs recursesubdirs; Tasks: installService 

; user feedback of waptservice activity
Source: "..\wapttray.exe"; DestDir: "{app}"; BeforeInstall: killtask('wapttray.exe'); 

; command line tools
Source: "..\wapt-get.exe"; DestDir: "{app}";
Source: "..\wapt-get.exe.manifest"; DestDir: "{app}";
Source: "..\dmidecode.exe"; DestDir: "{app}";

; local package cache
Source: "..\cache\icons\unknown.png"; DestDir: "{app}\cache\icons";

; for openssl : Visual C++ 2008 redistributable
Source: "..\vc_redist\*"; DestDir: "{app}\vc_redist";

; config file sample
Source: "..\wapt-get.ini.tmpl"; DestDir: "{app}"; 

; authorized public keys
Source: "..\ssl\*"; DestDir: "{app}\ssl"; Flags: createallsubdirs recursesubdirs

[Dirs]
Name: "{app}"; Permissions: everyone-readexec authusers-readexec admins-full  

[Setup]
AppName={#AppName}
AppVersion={#AppVerStr}
AppVerName={#AppName} {#AppVerStr}
UninstallDisplayName={#AppName} {#AppVerStr}
VersionInfoVersion={#FileVerStr}
VersionInfoTextVersion={#AppVerStr}
AppCopyright={#Company}
DefaultGroupName={#AppName}
ChangesEnvironment=True
AppPublisher={#Company}
OutputDir={#output_dir}
SolidCompression=True
AppPublisherURL=http://www.tranquil.it
AppUpdatesURL=http://wapt.tranquil.it/wapt
AppSupportURL=http://dev.tranquil.it/index.php/WAPT_-_apt-get_pour_Windows
AppContact=wapt@lists.tranquil.it
AppSupportPhone=+33 2 40 97 57 55
CloseApplications=False
PrivilegesRequired=admin
MinVersion=0,5.0sp4
LicenseFile=..\COPYING.txt
RestartIfNeededByRun=False
SetupIconFile=..\wapt.ico



#ifdef signtool
SignTool={#signtool}
#endif

[Languages]
;Name: "en"; MessagesFile: "compiler:Default.isl"
Name:fr;MessagesFile: "compiler:Languages\French.isl"

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}')
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wapt-get.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\wapt-get.exe"; Flags: uninsdeletekey

[INI]

Filename: {app}\wapt-get.ini; Section: global; Key: waptupdate_task_period; String: {#default_update_period}; Flags:  createkeyifdoesntexist 
Filename: {app}\wapt-get.ini; Section: global; Key: waptupdate_task_maxruntime; String: {#default_update_maxruntime}; Flags: createkeyifdoesntexist

[Run]
Filename: "{app}\vc_redist\vcredist_x86.exe"; Parameters: "/q"; WorkingDir: "{tmp}"; StatusMsg: "Updating MS VC++ libraries for OpenSSL..."; Description: "Update MS VC++ libraries"; Tasks: installredist2008
;Filename: "{app}\wapt-get.exe"; Parameters: "upgradedb"; Flags: runhidden; StatusMsg: "Upgrading local sqlite database structure"; Description: "Upgrade packages list"
Filename: "{app}\wapt-get.exe"; Parameters: "--direct update"; Flags: runhidden; StatusMsg: "Updating packages list"; Description: "Update packages list from main repository"
Filename: "{app}\wapt-get.exe"; Parameters: "setup-tasks"; Tasks: setuptasks; Flags: runhidden; StatusMsg: "Setting up daily sheduled tasks"; Description: "Set up daily sheduled tasks"
; rights rw for Admins and System, ro for users and authenticated users on wapt directory
Filename: "cmd"; Parameters: "/C echo O| cacls {app} /S:""D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1201a9;;;AU)"""; Tasks:installService; Flags: runhidden; WorkingDir: "{tmp}"; StatusMsg: "Changing rights on wapt directory..."; Description: "Changing rights on wapt directory"

; if waptservice
Filename: "{app}\waptpython.exe"; Parameters: """{app}\waptservice\waptservice.py"" install"; Tasks:installService ; Flags: runhidden; StatusMsg: "Install waptservice"; Description: "Install WAPT Service"
Filename: "{app}\wapttray.exe"; Tasks: autorunTray; Flags: runminimized nowait runasoriginaluser skipifsilent postinstall; StatusMsg: "Launch WAPT tray icon"; Description: "Launch WAPT tray icon"

[Icons]
Name: "{commonstartup}\WAPT tray helper"; Tasks: autorunTray; Filename: "{app}\wapttray.exe"; Flags: excludefromshowinnewinstall;
[Tasks]
Name: setupTasks; Description: "Créer des tâches planifiées pour la mise à jour des paquets"; 
Name: installService; Description: "Installer Wapt en tant que service";
Name: autorunTray; Description: "Démarrer le WAPT Tray lors de l'ouverture de session"; Flags: unchecked;
Name: installredist2008; Description: "Install VC++ 2008 redistributables";

[UninstallRun]
Filename: "taskkill"; Parameters: "/t /im ""waptconsole.exe"" /f"; Flags: runhidden; StatusMsg: "Stopping waptconsole"
Filename: "taskkill"; Parameters: "/t /im ""wapttray.exe"" /f"; Flags: runhidden; StatusMsg: "Stopping wapt tray"
Filename: "net"; Parameters: "stop waptservice"; Flags: runhidden; StatusMsg: "Stop waptservice"
Filename: "sc"; Parameters: "delete waptservice"; Flags: runhidden; StatusMsg: "Uninstall waptservice"

[Code]
#include "services.iss"
var
  teWaptRepoUrl:TEdit;

function InitializeSetup(): Boolean;
var
  ResultCode: integer;
begin
  // terminate waptconsole
  if Exec('taskkill', '/t /im "waptconsole.exe" /f', '', SW_SHOW,
     ewWaitUntilTerminated, ResultCode) then
  begin
    // handle success if necessary; ResultCode contains the exit code
  end
  else begin
    // handle failure if necessary; ResultCode contains the error code
  end;

  // Proceed Setup
  if ServiceExists('waptservice') then
    SimpleStopService('waptservice',True,True);
  if ServiceExists('waptserver') then
    SimpleStopService('waptserver',True,True);
  if ServiceExists('waptmongodb') then
    SimpleStopService('waptmongodb',True,True);
  Result := True;
end;

procedure DeinitializeSetup();
begin
  if ServiceExists('waptservice') then
    SimpleStartService('waptservice',True,True); 
end;

function RunCmd(cmd:String;RaiseOnError:Boolean):String;
var
  ErrorCode: Integer;
  TmpFileName, ExecStdout: string;
begin
  Result := 'Error';
  TmpFileName := ExpandConstant('{tmp}') + '\runresult.txt';
  try
    Exec('cmd','/C '+cmd+'  > "' + TmpFileName + '"', '', SW_HIDE,
      ewWaitUntilTerminated, ErrorCode);
    if RaiseOnError and (ErrorCode>0) then
       RaiseException('La commande '+cmd+' a renvoyÃ© le code d''erreur '+intToStr(ErrorCode));
    if LoadStringFromFile(TmpFileName, ExecStdout) then 
      result := ExecStdOut
    else 
      result:='';
  finally
    if FileExists(TmpFileName) then
	     DeleteFile(TmpFileName);
  end;
end;

procedure killtask(name:String);
var
  errorcode:integer;
begin
  shellexec('','taskkill','/t /im "'+name+'" /f','',sw_Hide,ewWaitUntilTerminated,Errorcode);
end;

function NeedsAddPath(Param: string): boolean;
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

