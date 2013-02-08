
#define AppName "WAPT"
#define AppVersion GetFileVersion(AddBackslash(SourcePath) + "wapt-get.exe")

[Files]
Source: "C:\tranquilit\wapt\DLLs\*"; DestDir: "{app}\DLLs"; Flags: createallsubdirs recursesubdirs
Source: "C:\tranquilit\wapt\dns\*"; DestDir: "{app}\dns"; Flags: createallsubdirs recursesubdirs
Source: "C:\tranquilit\wapt\iniparse\*"; DestDir: "{app}\iniparse"; Flags: createallsubdirs recursesubdirs
Source: "C:\tranquilit\wapt\lib\*"; DestDir: "{app}\lib"; Flags: createallsubdirs recursesubdirs ; Excludes: "*.pyc,test,*.~*" 
Source: "C:\tranquilit\wapt\libs\*"; DestDir: "{app}\libs"; Flags: createallsubdirs recursesubdirs
Source: "C:\tranquilit\wapt\static\*"; DestDir: "{app}\static"; Flags: createallsubdirs recursesubdirs
Source: "C:\tranquilit\wapt\templates\*"; DestDir: "{app}\templates"; Flags: createallsubdirs recursesubdirs
Source: "C:\tranquilit\wapt\utils\*"; DestDir: "{app}\utils"; Flags: createallsubdirs recursesubdirs
Source: "C:\tranquilit\wapt\common.py"; DestDir: "{app}"; 
Source: "C:\tranquilit\wapt\winshell.py"; DestDir: "{app}"; 
Source: "C:\tranquilit\wapt\setuphelpers.py"; DestDir: "{app}"; 
Source: "C:\tranquilit\wapt\sqlite3.dll"; DestDir: "{app}"; 
Source: "C:\tranquilit\wapt\Microsoft.VC90.CRT.manifest"; DestDir: "{app}";
Source: "C:\tranquilit\wapt\msvcm90.dll"; DestDir: "{app}";
Source: "C:\tranquilit\wapt\msvcp90.dll"; DestDir: "{app}";
Source: "C:\tranquilit\wapt\msvcr90.dll"; DestDir: "{app}";
Source: "C:\tranquilit\wapt\python27.dll"; DestDir: "{app}";
Source: "C:\tranquilit\wapt\pythoncom27.dll"; DestDir: "{app}";
Source: "C:\tranquilit\wapt\pythoncomloader27.dll"; DestDir: "{app}";
Source: "C:\tranquilit\wapt\pywintypes27.dll"; DestDir: "{app}";
Source: "C:\tranquilit\wapt\wapt-get.ini"; DestDir: "{app}";
Source: "C:\tranquilit\wapt\waptservice.exe"; DestDir: "{app}";  BeforeInstall: BeforeWaptServiceInstall('waptservice.exe'); AfterInstall: AfterWaptServiceInstall('waptservice.exe');
Source: "C:\tranquilit\wapt\wapt-get.py"; DestDir: "{app}"; 
Source: "C:\tranquilit\wapt\wapt-get.exe.manifest"; DestDir: "{app}";
Source: "C:\tranquilit\wapt\wapt-get.exe"; DestDir: "{app}";


[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
DefaultDirName={pf}\{#AppName}
DefaultGroupName={#AppName}
ChangesEnvironment=True
AppPublisher=Tranquil IT Systems
UninstallDisplayName=WAPT libraries and WAPTService
OutputDir=setup
OutputBaseFilename=WaptSetup
SolidCompression=True

[Run]


[UninstallRun]
Filename: "{app}\waptservice.exe"; Parameters: "--install"

[Code]
#include "services.iss"

function InitializeSetup(): Boolean;
begin
  if ServiceExists('waptservice') then
    SimpleStopService('waptservice',True,True);
  Result := True;
end;

procedure DeinitializeSetup();
begin
  if ServiceExists('waptservice') then
    SimpleStartService('waptservice',True,True);
end;

procedure AfterWaptServiceinstall(exe:String);
begin
  SimpleCreateService(
    'waptservice',
    'waptservice', 
    ExpandConstant('{app}\waptservice.exe'),
    SERVICE_AUTO_START,
    '','', 
    False, 
    False);
end;

procedure BeforeWaptServiceinstall(exe:String);
begin
  if ServiceExists('waptservice') then
  begin
    SimpleStopService('waptservice',True,True);
    SimpleDeleteService('waptservice');
  end;
end;

