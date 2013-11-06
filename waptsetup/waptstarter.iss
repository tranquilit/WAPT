#define Company "Tranquil IT Systems"
#define SrcApp AddBackslash(SourcePath) + "..\wapt-get.exe"
#define FileVerStr GetFileVersion(SrcApp)
#define StripBuild(str VerStr) Copy(VerStr, 1, RPos(".", VerStr)-1)
#define AppVerStr StripBuild(FileVerStr)
#define default_repo_url "http://wapt.tranquil.it/wapt"
#define default_wapt_server "http://wapt:8080"
#define default_update_period "120"
#define default_update_maxruntime "30"

#define output_dir "."

#define AppName "WAPT"



[Files]
Source: "..\DLLs\*"; DestDir: "{app}\DLLs"; Flags: createallsubdirs recursesubdirs
Source: "..\lib\*"; DestDir: "{app}\lib"; Flags: createallsubdirs recursesubdirs ; Excludes: "*.pyc,test,*.~*" 
Source: "..\libs\*"; DestDir: "{app}\libs"; Flags: createallsubdirs recursesubdirs  ; Excludes: "*.pyc,test,*.~*" 
Source: "..\ssl\*"; DestDir: "{app}\ssl"; Flags: createallsubdirs recursesubdirs
Source: "..\templates\*"; DestDir: "{app}\templates"; Flags: createallsubdirs recursesubdirs
Source: "..\common.py"; DestDir: "{app}"; 
Source: "..\waptpackage.py"; DestDir: "{app}"; 
Source: "..\setuphelpers.py"; DestDir: "{app}"; 
Source: "..\sqlite3.dll"; DestDir: "{app}"; 
Source: "..\Microsoft.VC90.CRT.manifest"; DestDir: "{app}";
Source: "..\msvcm90.dll"; DestDir: "{app}";
Source: "..\msvcp90.dll"; DestDir: "{app}";
Source: "..\msvcr90.dll"; DestDir: "{app}";
Source: "..\python27.dll"; DestDir: "{app}";
Source: "..\pythoncom27.dll"; DestDir: "{app}";
Source: "..\pythoncomloader27.dll"; DestDir: "{app}";
Source: "..\pywintypes27.dll"; DestDir: "{app}";
Source: "..\wapt-get.ini.tmpl"; DestDir: "{app}"; 
Source: "..\wapt-get.py"; DestDir: "{app}"; 
Source: "..\keyfinder.py"; DestDir: "{app}"; 
Source: "..\waptdevutils.py"; DestDir: "{app}"; 
Source: "..\wapt-get.exe.manifest"; DestDir: "{app}";
Source: "..\wapt-get.exe"; DestDir: "{app}";
Source: "..\waptconsole.exe.manifest"; DestDir: "{app}";
Source: "..\waptconsole.exe"; DestDir: "{app}";
Source: "..\waptdevutils.py"; DestDir: "{app}";
Source: "..\dmidecode.exe"; DestDir: "{app}";
Source: "..\wapt.ico"; DestDir: "{app}";
Source: "innosetup\*"; DestDir: "{app}\waptsetup\innosetup";
Source: "wapt.iss"; DestDir: "{app}\waptsetup";
Source: "services.iss"; DestDir: "{app}\waptsetup";
Source: "..\COPYING.txt"; DestDir: "{app}";
Source: "..\wapttray.exe"; DestDir: "{app}"; BeforeInstall: killtask('wapttray.exe'); 
Source: "..\vc_redist\*"; DestDir: "{app}\vc_redist";
Source: "..\lib\site-packages\M2Crypto\libeay32.dll" ; DestDir: "{app}"; 
Source: "..\lib\site-packages\M2Crypto\ssleay32.dll" ; DestDir: "{app}";

Source: "..\waptpython.exe"; DestDir: "{app}";
Source: "..\waptservice\static\*"; DestDir: "{app}\waptservice\static"; Flags: createallsubdirs recursesubdirs
Source: "..\waptservice\ssl\*"; DestDir: "{app}\waptservice\ssl"; Flags: createallsubdirs recursesubdirs
Source: "..\waptservice\templates\*"; DestDir: "{app}\waptservice\templates"; Flags: createallsubdirs recursesubdirs
Source: "..\python27.dll"; DestDir: "{sys}"; Flags: sharedfile 32bit;
Source: "..\waptservice\waptservice*.py"; DestDir: "{app}\waptservice\";BeforeInstall: BeforeWaptServiceInstall('waptservice.py')


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
DefaultDirName={pf}\wapt
DefaultGroupName={#AppName}
ChangesEnvironment=True
AppPublisher={#Company}
OutputDir={#output_dir}
OutputBaseFilename=waptstarter


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

;SignTool=kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}')
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wapt-get.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\wapt-get.exe"; Flags: uninsdeletekey

[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {#default_repo_url}
Filename: {app}\wapt-get.ini; Section: global; Key: waptupdate_task_period; String: {#default_update_period}; Flags:  createkeyifdoesntexist 
Filename: {app}\wapt-get.ini; Section: global; Key: waptupdate_task_maxruntime; String: {#default_update_maxruntime}; Flags: createkeyifdoesntexist
;Filename: {app}\wapt-get.ini; Section: tranquilit; Key: repo_url; String: http://wapt.tranquil.it/wapt; Tasks: usetispublic; Flags: createkeyifdoesntexist
;Filename: {app}\wapt-get.ini; Section: global; Key: repositories; String: tranquilit; Flags: createkeyifdoesntexist; Tasks: useTISPublic

[Run]
Filename: "{app}\vc_redist\vcredist_x86.exe"; Parameters: "/q"; WorkingDir: "{tmp}"; StatusMsg: "Updating MS VC++ libraries for OpenSSL..."; Description: "Update MS VC++ libraries"
Filename: "{app}\wapt-get.exe"; Parameters: "upgradedb"; Flags: runhidden; StatusMsg: "Upgrading local sqlite database structure"; Description: "Upgrade packages list"
Filename: "{app}\wapt-get.exe"; Parameters: "update"; Flags: runhidden; StatusMsg: "Updating packages list"; Description: "Update packages list from main repository"
Filename: "{app}\wapt-get.exe"; Parameters: "setup-tasks"; Flags: runhidden; StatusMsg: "Setting up daily sheduled tasks"; Description: "Set up daily sheduled tasks"
FileName: "{app}\waptpython.exe"; Parameters: """{app}\waptservice\waptservice_servicewrapper.py"" --startup=auto install"; Flags: runhidden; StatusMsg: "Install waptservice"
; rights rw for Admins and System, ro for users and authenticated users
Filename: "cmd"; Parameters: "/C echo O| cacls {app} /S:""D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1201a9;;;AU)"""; Flags: runhidden; WorkingDir: "{tmp}"; StatusMsg: "Changing rights on wapt directory..."; Description: "Changing rights on wapt directory"
Filename: "{app}\wapttray.exe"; Flags: runminimized nowait runasoriginaluser postinstall; StatusMsg: "Launch WAPT tray icon"; Description: "Launch WAPT tray icon"

[Icons]
Name: "{commonstartup}\WAPT tray helper";  Filename: "{app}\wapttray.exe"; Flags: excludefromshowinnewinstall;
Name: "{commonstartup}\WAPT session setup";Filename: "{app}\wapt-get.exe"; Parameters: "session-setup ALL"; Flags: runminimized excludefromshowinnewinstall;


[UninstallRun]
Filename: "taskkill"; Parameters: "/t /im ""waptconsole.exe"" /f"; Flags: runhidden; StatusMsg: "Stopping waptconsole"
Filename: "taskkill"; Parameters: "/t /im ""wapttray.exe"" /f"; Flags: runhidden; StatusMsg: "Stopping wapt tray"
Filename: "net"; Parameters: "stop waptservice"; Flags: runhidden; StatusMsg: "Stop waptservice"
FileName: "{app}\waptpython.exe"; Parameters: "{app}\waptservice\waptservice_servicewrapper.py uninstall"; Flags: runhidden; StatusMsg: "Remove waptservice"
; Filename: "{app}\waptservice.exe"; Parameters: "--uninstall"; Flags: runhidden; StatusMsg: "Uninstall waptservice"

[Code]
#include "services.iss"
var
  rbCustomUrl,rbDnsServer: TNewRadioButton;
  teWaptUrl,teWaptServerUrl: TEdit;
  CustomPage: TWizardPage;
  
procedure CurPageChanged(CurPageID: Integer);
var
  WaptRepo: String;
begin
end;

function GetRepoURL(Param: String):String;
begin
  if WizardSilent then
    result :='http://wapt/wapt';
end;

function GetWaptServerURL(Param: String):String;
begin
  if WizardSilent then
    result := 'http://wapt:8080';
end;


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
       RaiseException('La commande '+cmd+' a renvoyé le code d''erreur '+intToStr(ErrorCode));
    if LoadStringFromFile(TmpFileName, ExecStdout) then 
      result := ExecStdOut
    else 
      result:='';
  finally
    if FileExists(TmpFileName) then
	     DeleteFile(TmpFileName);
  end;
end;

procedure AfterWaptServiceinstall();
var
  ErrorCode: Integer;
  ExecStdout: string;
  winver: TWindowsVersion ;
begin
  if not Exec(ExpandConstant('{app}\waptpython.exe'),
     ExpandConstant('{app}\waptservice\waptservice_servicewrapper.py --startup=auto install'), 
     '', 
     SW_HIDE, 
     ewWaitUntilTerminated, ErrorCode) then
    RaiseException('Error installing waptservice: '+intToStr(ErrorCode)) 
end;


procedure BeforeWaptServiceinstall();
begin
  if ServiceExists('waptservice') then
    SimpleDeleteService('waptservice');
end;

procedure beforeUpdateWapt();
var
  WinHttpReq: Variant;
begin
  try
    WinHttpReq := CreateOleObject('WinHttp.WinHttpRequest.5.1');
    WinHttpReq.Open('GET', teWaptUrl.Text, false);
    WinHttpReq.Send();
  except
    MsgBox('WAPT repository URL is invalid/unreachable.'#13#10' please check repo_url in "wapt-get.ini" file', mbError, MB_OK);
  end;
  if WinHttpReq.Status <> 200 then
    MsgBox('WAPT repository URL is invalid/unreachable.'#13#10' please check repo_url in "wapt-get.ini" file', mbError, MB_OK);
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

