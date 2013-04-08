
#define AppName "WAPT"
#define AppVersion GetFileVersion(AddBackslash(SourcePath) + "..\wapt-get.exe")

[Files]
Source: "..\DLLs\*"; DestDir: "{app}\DLLs"; Flags: createallsubdirs recursesubdirs
Source: "..\lib\*"; DestDir: "{app}\lib"; Flags: createallsubdirs recursesubdirs ; Excludes: "*.pyc,test,*.~*" 
Source: "..\libs\*"; DestDir: "{app}\libs"; Flags: createallsubdirs recursesubdirs
Source: "..\static\*"; DestDir: "{app}\static"; Flags: createallsubdirs recursesubdirs
Source: "..\templates\*"; DestDir: "{app}\templates"; Flags: createallsubdirs recursesubdirs
Source: "..\ssl\*"; DestDir: "{app}\ssl"; Flags: createallsubdirs recursesubdirs
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
Source: "..\waptservice.exe"; DestDir: "{app}";  BeforeInstall: BeforeWaptServiceInstall('waptservice.exe'); AfterInstall: AfterWaptServiceInstall('waptservice.exe'); Tasks: installService
Source: "..\wapt-get.ini.tmpl"; DestDir: "{app}"; 
Source: "..\wapt-get.py"; DestDir: "{app}"; 
Source: "..\wapt-get.exe.manifest"; DestDir: "{app}";
Source: "..\wapt-get.exe"; DestDir: "{app}";
Source: "..\wapttray.exe"; DestDir: "{app}"; BeforeInstall: killtask('wapttray.exe')
Source: "..\vc_redist\*"; DestDir: "{tmp}\vc_redist";


[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
DefaultDirName="C:\{#AppName}"
DefaultGroupName={#AppName}
ChangesEnvironment=True
AppPublisher=Tranquil IT Systems
UninstallDisplayName=WAPT libraries and WAPTService
OutputDir="."
OutputBaseFilename=waptsetup
SolidCompression=True
AppPublisherURL=http://www.tranquil.it
AppUpdatesURL=http://wapt.tranquil.it
AppContact=dev@tranquil.it
AppSupportPhone=+33 2 40 97 57 55
SignTool=kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f
CloseApplications=False
PrivilegesRequired=admin

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}')

[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: repo_url; String: {code:GetRepoURL}
Filename: {app}\wapt-get.ini; Section: global; Key: public_cert; String: {code:GetPublicCert}

[Run]
Filename: "msiexec.exe"; Parameters: "/q /i ""{tmp}\vc_redist\vc_red.msi"""
Filename: "{app}\wapt-get.exe"; Parameters: "upgradedb"; Flags: runhidden 
Filename: "{app}\wapt-get.exe"; Parameters: "update"; Tasks: updateWapt; Flags: runhidden
Filename: "{app}\wapttray.exe"; Flags: runminimized nowait runasoriginaluser

[Icons]
Name: "{commonstartup}\WAPT tray helper"; Filename: "{app}\wapttray.exe";


[Tasks]
Name: updateWapt; Description: "Lancer la mise à jour des paquets après l'installation";
Name: installService; Description: "installation du service WAPT";


[UninstallRun]
Filename: "taskkill"; Parameters: "/t /im ""wapttray.exe"" /f"; Flags: runhidden
Filename: "net"; Parameters: "stop waptservice"; Flags: runhidden
Filename: "{app}\waptservice.exe"; Parameters: "--uninstall"; Flags: runhidden


[Code]
#include "services.iss"
var
  rbCustomRepo: TNewRadioButton;
  rbDnsRepo: TNewRadioButton;
  cbWaptUpdate : TCheckbox ;
  bIsVerySilent: boolean;
  teWaptUrl,teWaptPublicCert: TEdit;
  lab1:TLabel;
  
procedure InitializeWizard;
var
  CustomPage: TWizardPage;

begin
  CustomPage := CreateCustomPage(wpSelectTasks, 'Installation type', '');

  rbCustomRepo := TNewRadioButton.Create(WizardForm);
  rbCustomRepo.Parent := CustomPage.Surface;
  rbCustomRepo.Checked := True;
  rbCustomRepo.Caption := 'Dépôt WAPT';
  
  teWaptUrl :=TEdit.Create(WizardForm);
  teWaptUrl.Parent := CustomPage.Surface; 
  teWaptUrl.Left :=rbCustomRepo.Left + rbCustomRepo.Width;
  teWaptUrl.Width :=CustomPage.SurfaceWidth - rbCustomRepo.Width;
  

  
  rbDnsRepo := TNewRadioButton.Create(WizardForm);
  rbDnsRepo.Parent := CustomPage.Surface;
  rbDnsRepo.Top := rbCustomRepo.Top + rbCustomRepo.Height + ScaleY(15);
  rbDnsRepo.Width := CustomPage.SurfaceWidth;
  rbDnsRepo.Caption := 'Auto détection du dépôt grâce au DNS';


  lab1 := TLabel.Create(WizardForm);
  lab1.Caption := 'Certificat public:';
  lab1.autosize := True;
  lab1.Parent := CustomPage.Surface; 
  lab1.Left := rbDnsRepo.Left;
  lab1.Top := rbDnsRepo.Top + rbDnsRepo.Height + ScaleY(15);

  teWaptPublicCert :=TEdit.Create(WizardForm);
  teWaptPublicCert.Parent := CustomPage.Surface; 
  teWaptPublicCert.Left := lab1.left+lab1.width+5;
  teWaptPublicCert.Top := rbDnsRepo.Top + rbDnsRepo.Height + ScaleY(15);
  teWaptPublicCert.Width := 300;
  
  
//  cbWaptUpdate := TCheckbox.Create(WizardForm);
//  cbWaptUpdate.Parent := CustomPage.Surface;
//  cbWaptUpdate.Top := rbDnsRepo.Top + rbDnsRepo.Height + ScaleY(15);
//  cbWaptUpdate.Width := CustomPage.SurfaceWidth;
//  cbWaptUpdate.checked := True;
//  cbWaptUpdate.Caption := 'mise à jour de la liste des paquets'
  
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if curPageId=wpSelectTasks then
  begin
    teWaptUrl.Text := GetIniString('Global', 'repo_url', 'http://wapt.tranquil.it/wapt', ExpandConstant('{app}\wapt-get.ini'));
    rbCustomRepo.Checked := teWaptUrl.Text <> ''; 
    rbDnsRepo.Checked := teWaptUrl.Text = ''; 
    teWaptPublicCert.Text := GetIniString('Global', 'public_cert', ExpandConstant('{app}\ssl\tranquilit.crt'), ExpandConstant('{app}\wapt-get.ini'));
  end;
end;

function GetRepoURL(Param: String):String;
begin
  if WizardSilent then
    result := GetIniString('Global', 'repo_url', 'http://wapt.tranquil.it/wapt',ExpandConstant('{app}\wapt-get.ini'))
  else
    if rbCustomRepo.Checked then
       result := teWaptUrl.Text
    else 
       result :='';
end;

function GetPublicCert(Param: String):String;
begin
  if WizardSilent then
    result := GetIniString('Global', 'public_cert', ExpandConstant('{app}\ssl\tranquilit.crt'), ExpandConstant('{app}}\wapt-get.ini'))
  else
    result := teWaptPublicCert.Text;
end;

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
var
  ErrorCode: Integer;
begin
//  SimpleCreateService(
//   'waptservice',
//    'waptservice', 
//    ExpandConstant('"{app}\waptservice.exe" --run'),
//    SERVICE_AUTO_START,
//    '','', 
//    False, 
//    False);
  if not ShellExec('', ExpandConstant('{app}\waptservice.exe'),
     '--install', '{app}', SW_HIDE, True, ErrorCode) then
  begin
    RaiseException('Error installing waptservice:'+intToStr(ErrorCode));
  end;
   
end;

procedure BeforeWaptServiceinstall(exe:String);
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
    MsgBox('l''url du dépôt WAPT est invalide.'#13#10' Veuillez corriger le fichier "C:\WAPT\wapt-get.ini"', mbError, MB_OK);
  end;
  if WinHttpReq.Status <> 200 then
    begin
    MsgBox('l''url du dépôt WAPT est invalide.'#13#10' Veuillez corriger le fichier "C:\WAPT\wapt-get.ini"', mbError, MB_OK);
    end
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


