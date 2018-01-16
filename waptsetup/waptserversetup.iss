#ifndef edition

#define edition "waptserversetup"
#define AppName "WAPT Server"
#define default_repo_url "http://127.0.0.1/wapt/"
#define default_wapt_server "http://127.0.0.1"

#define repo_url ""
#define wapt_server ""

#define output_dir "."
#define Company "Tranquil IT Systems"

#define send_usage_report "1"

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
;#define FastDebug

;#define choose_components

#endif

#include "waptsetup.iss"

[Files]

; server postconf utility
#ifdef choose_components
Source: "..\waptserverpostconf.exe"; DestDir: "{app}"; Flags: ignoreversion; Tasks: InstallWaptserver
#else
Source: "..\waptserverpostconf.exe"; DestDir: "{app}"; Flags: ignoreversion;
#endif

; deployment/upgrade tool
Source: "..\waptdeploy.exe"; DestDir: "{app}\waptserver\repository\wapt\"; Flags: ignoreversion

#ifdef choose_components
Source: "..\waptserver\waptserver.ini.template"; DestDir: "{app}\conf"; DestName: "waptserver.ini"; Tasks: InstallWaptserver
Source: "..\waptserver\*.py"; DestDir: "{app}\waptserver"; Tasks: InstallWaptserver       
Source: "..\waptserver\*.template"; DestDir: "{app}\waptserver"; Tasks: InstallWaptserver
Source: "..\waptserver\templates\*"; DestDir: "{app}\waptserver\templates"; Flags: createallsubdirs recursesubdirs; Tasks: InstallWaptserver
Source: "..\waptserver\translations\*"; DestDir: "{app}\waptserver\translations"; Flags: createallsubdirs recursesubdirs; Tasks: InstallWaptserver
Source: "..\waptserver\scripts\*"; DestDir: "{app}\waptserver\scripts"; Flags: createallsubdirs recursesubdirs; Tasks: InstallWaptserver
Source: "..\waptserver\pgsql\*"; DestDir: "{app}\waptserver\pgsql"; Flags: createallsubdirs recursesubdirs; Tasks: InstallPostgreSQL
Source: "..\waptserver\nginx\*"; DestDir: "{app}\waptserver\nginx"; Flags: createallsubdirs recursesubdirs; Tasks: InstallNGINX
#else
Source: "..\waptserver\waptserver.ini.template"; DestDir: "{app}\conf"; DestName: "waptserver.ini"; 
Source: "..\waptserver\*.py"; DestDir: "{app}\waptserver";   
Source: "..\waptserver\*.template"; DestDir: "{app}\waptserver"; 
Source: "..\waptserver\templates\*"; DestDir: "{app}\waptserver\templates"; Flags: createallsubdirs recursesubdirs;
Source: "..\waptserver\translations\*"; DestDir: "{app}\waptserver\translations"; Flags: createallsubdirs recursesubdirs; 
Source: "..\waptserver\scripts\*"; DestDir: "{app}\waptserver\scripts"; Flags: createallsubdirs recursesubdirs;
Source: "..\waptserver\pgsql\*"; DestDir: "{app}\waptserver\pgsql"; Flags: createallsubdirs recursesubdirs;
Source: "..\waptserver\nginx\*"; DestDir: "{app}\waptserver\nginx"; Flags: createallsubdirs recursesubdirs;
#endif

; For UninstallRun
Source: "..\waptserver\uninstall-services.bat"; Destdir: "{app}\waptserver\"

[Dirs]
Name: "{app}\waptserver\repository"
Name: "{app}\waptserver\log"
Name: "{app}\waptserver\repository\wapt"
Name: "{app}\waptserver\repository\wapt-host"
Name: "{app}\waptserver\repository\wapt-group"
Name: "{app}\waptserver\nginx\ssl"

[INI]
Filename: {app}\conf\waptserver.ini; Section: options; Key: allow_unauthenticated_registration; String: True;


[RUN]
Filename: "{app}\waptserver\pgsql\vcredist_x64.exe"; Parameters: "/passive /quiet"; StatusMsg: {cm:InstallMSVC2013}; Description: "{cm:InstallMSVC2013}";  
Filename: "{app}\waptserverpostconf.exe"; Parameters: "-l {code:CurrentLanguage}"; Flags: nowait postinstall runascurrentuser skipifsilent; StatusMsg: {cm:LaunchingPostconf}; Description: "{cm:LaunchingPostconf}"

[Tasks]
#ifdef choose_components
Name: InstallNGINX; Description: "{cm:InstallNGINX}"; GroupDescription: "WAPTServer"
Name: InstallPostgreSQL; Description: "{cm:InstallPostgreSQL}"; GroupDescription: "WAPTServer"
Name: InstallWaptserver; Description: "{cm:InstallWaptServer}"; GroupDescription: "WAPTServer"
#endif

[UninstallRun]
Filename: "{app}\waptserver\uninstall-services.bat"; Flags: runhidden; StatusMsg: "Stopping and deregistering waptserver"

[CustomMessages]
fr.RegisteringService=Mise en place du service WaptServer
fr.InstallMSVC2013=Installation de MSVC++ 2013 Redistribuable
fr.LaunchingPostconf=Lancement de la post-configuration du serveur
fr.InstallNGINX=Installer le serveur http NGINX (utlise les ports 80 et 443)
fr.InstallPostgreSQL=Installer le serveur PostgreSQL
fr.InstallWaptServer=Installer le serveur Wapt

en.RegisteringService=Setup WaptServer Service
en.InstallMSVC2013=Installing MSVC++ 2013 Redistribuable
en.LaunchingPostconf=Launch server post-configuration
en.InstallNGINX=Install NGINX http server(will use ports 80 and 443)
en.InstallPostgreSQL=Install PostgreSQL Server
en.InstallWaptServer=Install Wapt server

de.RegisteringService=Setup WaptServer Service
de.InstallMSVC2013=MSVC++ 2013 Redistribuable installieren
de.LaunchingPostconf=Server Post-Konfiguration starten
de.InstallNGINX=NGINX installieren http Server
de.InstallPostgreSQL=PostgreSQL Server installieren
en.InstallWaptServer=Wapt server installieren


[Code]
 
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

    Exec('net', 'stop waptpostgresql', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('net', 'stop waptmongodb', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('net', 'stop waptnginx', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('net', 'stop waptserver', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('net', 'stop waptapache', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

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

    repeat
      ConflictingService := '';

      NetstatOutput := RunCmd('netstat -a -n -p tcp', True);
      if Pos('0.0.0.0:443 ', NetstatOutput) > 0 then
        ConflictingService := '443'
  #ifdef waptserver
      else if Pos('0.0.0.0:443 ', NetstatOutput) > 0 then
        ConflictingService := '443'
  #endif
      ;

      if ConflictingService <> '' then
      begin
        Reply := MsgBox('A conflicting service is running on port '+ConflictingService+'. '+
                        'This is not supported and you should probably abort the installer. '+
                        'Visit http://dev.tranquil.it/ for documentation about WAPT.',
                        mbError, MB_ABORTRETRYIGNORE);
        if Reply = IDABORT then
          Abort;
      end;
    until (ConflictingService = '') or (Reply = IDIGNORE);
    
    //Result := True;
  end
  else if CurStep = ssDone then
  begin
    if ServiceExists('waptservice') then
      SimpleStartService('waptservice',True,True);
  end;
end;

{
procedure DeinitializeSetup();
begin
end;
}

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

