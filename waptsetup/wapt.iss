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
Source: "..\waptexit.exe"; DestDir: "{app}";

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

[Run]
Filename: "{app}\vc_redist\vcredist_x86.exe"; Parameters: "/q"; WorkingDir: "{tmp}"; StatusMsg: "Mise à jour des librairies MS VC++ pour openssl"; Description: "Mise à jour des librairies MS VC++"; Tasks: installredist2008
; Duplication necessaire, cf. [Tasks]
Filename: "{app}\vc_redist\vcredist_x86.exe"; Parameters: "/q"; WorkingDir: "{tmp}"; StatusMsg: "Mise à jour des librairies MS VC++ pour openssl"; Description: "Mise à jour des librairies MS VC++"; Tasks: installredist2008unchecked
;Filename: "{app}\wapt-get.exe"; Parameters: "upgradedb"; Flags: runhidden; StatusMsg: "Upgrading local sqlite database structure"; Description: "Upgrade packages list"
; rights rw for Admins and System, ro for users and authenticated users on wapt directory
Filename: "cmd"; Parameters: "/C echo O| cacls {app} /S:""D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1201a9;;;AU)"""; Tasks:installService; Flags: runhidden; WorkingDir: "{tmp}"; StatusMsg: "Mise en place des droits sur le répertoire wapt..."; Description: "Mise en place des droits sur le répertoire wapt"

; if waptservice
Filename: "{app}\waptpython.exe"; Parameters: """{app}\waptservice\waptservice.py"" install"; Tasks:installService ; Flags: runhidden; StatusMsg: "Installation du service WAPT"; Description: "Installation du service WAPT"
Filename: "{app}\wapttray.exe"; Tasks: autorunTray; Flags: runminimized nowait runasoriginaluser skipifsilent postinstall; StatusMsg: "Lancement de l'icône de notification"; Description: "Lancement de l'icône de notification"

[Icons]
Name: "{commonstartup}\WAPT tray helper"; Tasks: autorunTray; Filename: "{app}\wapttray.exe"; Flags: excludefromshowinnewinstall;

[Tasks]
Name: installService; Description: "Installer le service WAPT";
Name: autorunTray; Description: "Lancer l'icône de notification lors de l'ouverture de session"; Flags: unchecked;
Name: installredist2008; Description: "Installer les redistribuables VC++ 2008 (pour openssl)";  Check: VCRedistNeedsInstall();
; Duplication helas necessaire.
; On souhaite seulement changer les actions a realiser par defaut, pas a empecher
; l'utilisateur de forcer la reinstallation de VC++, et il n'existe pas de moyen
; de modifier dynamiquement le flag "unchecked" 
Name: installredist2008unchecked; Description: "Forcer la réinstallation des redistribuables VC++ 2008 (pour openssl)"; Check: not VCRedistNeedsInstall(); Flags: unchecked
Name: autoUpgradePolicy; Description: "Proposer la mise à jour des paquets à l'extinction du poste";

[UninstallRun]
Filename: "taskkill"; Parameters: "/t /im ""waptconsole.exe"" /f"; Flags: runhidden; StatusMsg: "Arrêt de waptconsole"
Filename: "taskkill"; Parameters: "/t /im ""wapttray.exe"" /f"; Flags: runhidden; StatusMsg: "Arrêt de l'icône de notification"
Filename: "net"; Parameters: "stop waptservice"; Flags: runhidden; StatusMsg: "Arrêt du service WAPT"
Filename: "sc"; Parameters: "delete waptservice"; Flags: runhidden; StatusMsg: "Désinstallation du service WAPT"

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
  if ServiceExists('waptapache') then
    SimpleStopService('waptapache',True,True);	
  if ServiceExists('waptmongodb') then
    SimpleStopService('waptmongodb',True,True);
  
  Result := True;
end;

procedure DeinitializeSetup();
begin
  if ServiceExists('waptservice') then
    SimpleStartService('waptservice',True,True); 
end;

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
