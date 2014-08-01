unit uVisServerPostconf;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, IpHtml, Ipfilebroker, RichView, vsVisualSynapse,
  RLRichText, Forms, Controls, Graphics, Dialogs, ComCtrls, StdCtrls, ExtCtrls,
  Buttons, ActnList, EditBtn, htmlview, Readhtml, Htmlsubs, IdHTTP,
  IdComponent,uvisLoading;

type

  { TVisWAPTServerPostConf }

  TVisWAPTServerPostConf = class(TForm)
    ActCheckDNS: TAction;
    ActCreateKey: TAction;
    ActCancel: TAction;
    ActBuildWaptsetup: TAction;
    actWriteConfStartServe: TAction;
    ActManual: TAction;
    ActNext: TAction;
    actPrevious: TAction;
    ActionList1: TActionList;
    BitBtn1: TBitBtn;
    ButPrevious: TBitBtn;
    ButNext: TBitBtn;
    BitBtn3: TBitBtn;
    BitBtn4: TBitBtn;
    BitBtn5: TBitBtn;
    BitBtn6: TBitBtn;
    Button1: TButton;
    cbLaunchWaptConsoleOnExit: TCheckBox;
    cbManualURL: TCheckBox;
    CBOpenFirewall: TCheckBox;
    DirectoryCert: TDirectoryEdit;
    edCommonName: TEdit;
    edCountry: TEdit;
    edOrgName: TEdit;
    edRepoUrl: TEdit;
    EdSourcesRoot: TLabeledEdit;
    edEmail: TEdit;
    EdPwd1: TEdit;
    EdPrivateKeyFN: TEdit;
    edLocality: TEdit;
    edOrganization: TEdit;
    EdKeyName: TEdit;
    EdPwd2: TEdit;
    edUnit: TEdit;
    edWaptServerUrl1: TEdit;
    fnPublicCert: TFileNameEdit;
    fnWaptDirectory: TDirectoryEdit;
    HTMLViewer1: THTMLViewer;
    Label1: TLabel;
    Label10: TLabel;
    Label12: TLabel;
    Label13: TLabel;
    Label14: TLabel;
    Label15: TLabel;
    Label16: TLabel;
    Label2: TLabel;
    EdWAPTServerName: TLabeledEdit;
    edWAPTRepoURL: TLabeledEdit;
    edWAPTServerURL: TLabeledEdit;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    Label9: TLabel;
    EdWaptServerIP: TLabeledEdit;
    EdWaptInifile: TMemo;
    EdTemplatesRepoURL: TLabeledEdit;
    EdDefaultPrefix: TLabeledEdit;
    Memo1: TMemo;
    Memo2: TMemo;
    Memo3: TMemo;
    Memo4: TMemo;
    Memo5: TMemo;
    Memo7: TMemo;
    Memo6: TMemo;
    PagesControl: TPageControl;
    Panel1: TPanel;
    Panel2: TPanel;
    panFinish: TPanel;
    pgParameters: TTabSheet;
    pgPassword: TTabSheet;
    ProgressBar1: TProgressBar;
    Shape1: TShape;
    StaticText1: TStaticText;
    pgStartServices: TTabSheet;
    pgDevparam: TTabSheet;
    pgPrivateKey: TTabSheet;
    pgFinish: TTabSheet;
    pgCreateWaptSetup: TTabSheet;
    procedure ActBuildWaptsetupExecute(Sender: TObject);
    procedure ActCheckDNSExecute(Sender: TObject);
    procedure ActCreateKeyExecute(Sender: TObject);
    procedure ActCreateKeyUpdate(Sender: TObject);
    procedure ActManualExecute(Sender: TObject);
    procedure ActManualUpdate(Sender: TObject);
    procedure ActNextExecute(Sender: TObject);
    procedure ActNextUpdate(Sender: TObject);
    procedure actPreviousExecute(Sender: TObject);
    procedure actPreviousUpdate(Sender: TObject);
    procedure actWriteConfStartServeExecute(Sender: TObject);
    procedure BitBtn3Click(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure EdKeyNameExit(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure HTMLViewer1HotSpotClick(Sender: TObject; const SRC: string;
      var Handled: boolean);
    procedure IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode;
      AWorkCount: Int64);
    procedure PagesControlChange(Sender: TObject);
  private
    CurrentVisLoading:TVisLoading;
    function CreateWaptSetup(default_public_cert: String='';
      default_repo_url: String=''; default_wapt_server: String='';
      destination: String=''; company: String='';OnProgress:TNotifyEvent = Nil): String;
    procedure OpenFirewall;
    { private declarations }
  public
    { public declarations }
  end;

var
  VisWAPTServerPostConf: TVisWAPTServerPostConf;

implementation
uses LCLIntf, Windows,WaptCommon,tisinifiles,superobject,tisutils,soutils,
    tiscommon,tisstrings,IniFiles,UnitRedirect,sha1,Regex,IdMultipartFormData,IdException;
{$R *.lfm}

{ TVisWAPTServerPostConf }

// qad %(key)s python format
function pyformat(template:String;params:ISuperobject):String;
var
  key,value:ISuperObject;
begin
  Result := template;
  for key in params.AsObject.GetNames do
    Result := StringReplace(Result,'%('+key.AsString+')s',params.S[key.AsString],[rfReplaceAll]);
end;

function WAPTServerJsonMultipartFilePost(waptserver,action: String;args:Array of const;
    FileArg,FileName:String; enableProxy:Boolean= False;
    user:AnsiString='';password:AnsiString='';OnHTTPWork:TWorkEvent=Nil):ISuperObject;
var
  res:String;
  http:TIdHTTP;
  St:TIdMultiPartFormDataStream;
begin
  if StrLeft(action,1)<>'/' then
    action := '/'+action;
  if length(args)>0 then
    action := format(action,args);
  HTTP := TIdHTTP.Create;
  St := TIdMultiPartFormDataStream.Create;
  try
    http.Request.BasicAuthentication:=True;
    http.Request.Username:=user;
    http.Request.Password:=password;
    http.OnWork:=OnHTTPWork;

    St.AddFile(FileArg,FileName);
    try
      res := HTTP.Post(waptserver+action,St);
    except
      on E:EIdException do ShowMessage(E.Message);
    end;
    result := SO(res);
  finally
    st.Free;
    HTTP.Free;
  end;
end;

function CreateSelfSignedCert(orgname,
        wapt_base_dir,
        destdir,
        country,
        locality,
        organization,
        orgunit,
        commonname,
        email:String
    ):String;
var
  opensslbin,opensslcfg,opensslcfg_fn,destpem,destcrt : String;
  params : ISuperObject;
begin
    destpem := AppendPathDelim(destdir)+orgname+'.pem';
    destcrt := AppendPathDelim(destdir)+orgname+'.crt';
    if not DirectoryExists(destdir) then
        mkdir(destdir);
    params := TSuperObject.Create;
    params.S['country'] := country;
    params.S['locality'] :=locality;
    params.S['organization'] := organization;
    params.S['unit'] := orgunit;
    params.S['commonname'] := commonname;
    params.S['email'] := email;

    opensslbin :=  AppendPathDelim(wapt_base_dir)+'lib\site-packages\M2Crypto\openssl.exe';
    opensslcfg :=  pyformat(FileToString(AppendPathDelim(wapt_base_dir) + 'templates\openssl_template.cfg'),params);
    opensslcfg_fn := AppendPathDelim(destdir)+'openssl.cfg';
    StringToFile(opensslcfg_fn,opensslcfg);
    try
      SetEnvironmentVariable(PAnsiChar('OPENSSL_CONF'),PAnsiChar(opensslcfg_fn));
      if ExecuteProcess(opensslbin,'req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout "'+destpem+'" -out "'+destcrt+'"',[]) <> 0 then
        result :=''
      else
        result := destpem;
    finally
      SysUtils.DeleteFile(opensslcfg_fn);
    end;
end;

function GetWaptServerURL: String;
begin
  result := IniReadString(WaptIniFilename,'Global','wapt_server');
end;

function GetWaptRepoURL: Utf8String;
begin
  result := IniReadString(WaptIniFilename,'Global','repo_url');
  if Result = '' then
      Result:='http://wapt/wapt';
  if result[length(result)] = '/' then
    result := copy(result,1,length(result)-1);
end;

procedure TVisWAPTServerPostConf.FormCreate(Sender: TObject);
begin
  PagesControl.ShowTabs:=False;
  PagesControl.ActivePageIndex:=0;
end;

procedure TVisWAPTServerPostConf.FormShow(Sender: TObject);
begin
  if GetServiceStatusByName('','WAPTServer') in  [ssRunning,ssPaused,ssPausePending,ssStartPending] then
    Sto_RedirectedExecute('cmd /C net stop waptserver');

  EdWAPTServerName.Text:=LowerCase(GetComputerName)+'.'+GetDNSDomain;
  if IniHasKey(WaptIniFilename,'global','default_package_prefix') then
    EdDefaultPrefix.Text:=IniReadString(WaptIniFilename,'global','default_package_prefix');
  if IniHasKey(WaptIniFilename,'global','default_sources_root') then
    EdSourcesRoot.Text:=IniReadString(WaptIniFilename,'global','default_sources_root');
  if IniHasKey(WaptIniFilename,'global','templates_repo_url') then
    EdTemplatesRepoURL.Text:=IniReadString(WaptIniFilename,'global','templates_repo_url');
  if IniHasKey(WaptIniFilename,'global','private_key') then
  begin
    EdPrivateKeyFN.Text:=IniReadString(WaptIniFilename,'global','private_key');
    EdKeyName.Text := ChangeFileExt(ExtractFileName(EdPrivateKeyFN.Text),'');
  end;
  PagesControlChange(Self);
end;

procedure TVisWAPTServerPostConf.HTMLViewer1HotSpotClick(Sender: TObject;
  const SRC: string; var Handled: boolean);
begin
  OpenURL(SRC);
  Handled:=True;
end;

procedure TVisWAPTServerPostConf.IdHTTPWork(ASender: TObject;
  AWorkMode: TWorkMode; AWorkCount: Int64);
begin
  if CurrentVisLoading<>Nil then
    CurrentVisLoading.DoProgress(ASender)
  else
  begin
    if ProgressBar1.Position>=ProgressBar1.Max then
      ProgressBar1.Position:=0
    else
      ProgressBar1.Position := ProgressBar1.Position+1;
    Application.ProcessMessages;
  end;
end;

procedure TVisWAPTServerPostConf.PagesControlChange(Sender: TObject);
var
  ini:TIniFile;

begin
  HTMLViewer1.LoadStrings(TMemo(FindComponent('Memo'+IntToStr(PagesControl.ActivePageIndex+1))).Lines);
  if PagesControl.ActivePage = pgStartServices then
  try
    ini := TMemIniFile.Create(WaptIniFilename);
    ini.WriteString('global','repo_url',edWAPTRepoURL.Text);
    ini.WriteString('global','wapt_server',edWAPTServerURL.Text);
    ini.WriteString('global','private_key',EdPrivateKeyFN.Text);
    ini.WriteString('global','templates_repo_url',EdTemplatesRepoURL.Text);
    ini.WriteString('global','default_sources_root',EdSourcesRoot.Text);
    ini.WriteString('global','default_package_prefix',EdDefaultPrefix.Text);
    ini.WriteString('global','loglevel','warning');
    EdWaptInifile.Lines.Clear;
    TMemIniFile(ini).GetStrings(EdWaptInifile.Lines);
  finally
    ini.Free;
  end
  else
  if PagesControl.ActivePage = pgFinish then
  begin
    HTMLViewer1.Parent := panFinish;
    HTMLViewer1.Align:=alClient;
  end
  else
  if PagesControl.ActivePage = pgCreateWaptSetup then
  begin
    ini := TIniFile.Create(WaptIniFilename);
    try
      fnPublicCert.Text:=ChangeFileExt(ini.ReadString('global', 'private_key', ''),'.crt');
      if not FileExists(fnPublicCert.Text) then
        fnPublicCert.Clear;
      edWaptServerUrl1.Text := ini.ReadString('global', 'wapt_server', '');
      edRepoUrl.Text := ini.ReadString('global', 'repo_url', '');
      edOrgName.Text := edOrganization.Text;
      fnWaptDirectory.Directory := GetTempDir(False);
    finally
      ini.Free;
    end;
  end;
end;

procedure TVisWAPTServerPostConf.OpenFirewall;
var
   output : String;
begin
  if GetServiceStatusByName('','SharedAccess') = ssRunning then
  begin
    output := Sto_RedirectedExecute('netsh firewall show portopening');
    if pos('waptserver',output)<=0 then
      Sto_RedirectedExecute(format('netsh.exe firewall add portopening name="waptserver %d" port=%d protocol=TCP',[waptserver_port,waptserver_port]))
  end
  else if GetServiceStatusByName('','MpsSvc') = ssRunning then
  begin
    output:='';
    try
      output := Sto_RedirectedExecute(format('netsh advfirewall firewall show rule name="waptserver %d"',[waptserver_port]));
    except
    end;
    if pos('waptserver',output)<=0 then
      output := Sto_RedirectedExecute(format('netsh advfirewall firewall add rule name="waptserver %d" dir=in localport=%d protocol=TCP action=allow',[waptserver_port,waptserver_port]));
  end;
end;


procedure TVisWAPTServerPostConf.ActManualUpdate(Sender: TObject);
begin
  if not ActManual.Checked then
  begin
    edWAPTRepoURL.Enabled := False;
    edWAPTServerURL.Enabled := False;
    edWAPTRepoURL.Text := Format('http://%s:8080/wapt',[EdWAPTServerName.Text]);
    edWAPTServerURL.Text := Format('http://%s:8080',[EdWAPTServerName.Text]);
  end
  else
  begin
    edWAPTRepoURL.Enabled := True;
    edWAPTServerURL.Enabled := True;
  end;
end;

procedure TVisWAPTServerPostConf.ActNextExecute(Sender: TObject);
begin
  if PagesControl.ActivePage<>pgFinish then
    PagesControl.ActivePageIndex := PagesControl.ActivePageIndex + 1
  else
  begin
    if cbLaunchWaptConsoleOnExit.Checked then
      OpenDocument(WaptBaseDir+'waptconsole.exe');
    ExitProcess(0);
  end;
end;

procedure TVisWAPTServerPostConf.ActNextUpdate(Sender: TObject);
begin
  if PagesControl.ActivePage = pgParameters then
    ActNext.Enabled := EdWaptServerIP.Text<>''
  else if PagesControl.ActivePage = pgPassword then
    ActNext.Enabled := (EdPwd1.Text<>'') and (EdPwd1.Text = EdPwd2.Text)
  else if PagesControl.ActivePage = pgPrivateKey then
    ActNext.Enabled := (EdPrivateKeyFN.Text<>'') and FileExists(EdPrivateKeyFN.Text)
  else if PagesControl.ActivePage = pgStartServices then
    ActNext.Enabled := GetServiceStatusByName('','waptserver') = ssRunning
  else
    ActNext.Enabled := PagesControl.ActivePageIndex<=PagesControl.PageCount-1;
  if PagesControl.ActivePageIndex=PagesControl.PageCount-1 then
    ActNext.Caption:='Fin'
  else
    ActNext.Caption:='Suivant';
end;

procedure TVisWAPTServerPostConf.actPreviousExecute(Sender: TObject);
begin
  PagesControl.ActivePageIndex := PagesControl.ActivePageIndex - 1;
end;

procedure TVisWAPTServerPostConf.actPreviousUpdate(Sender: TObject);
begin
  actPrevious.Enabled:=(PagesControl.ActivePageIndex>0) and (PagesControl.ActivePageIndex<PagesControl.PageCount-1);
end;

function runwapt(cmd:String):String;
begin
  StrReplace(cmd,'{app}',WaptBaseDir,[rfReplaceAll]);
  result := Sto_RedirectedExecute(cmd);
end;


procedure TVisWAPTServerPostConf.actWriteConfStartServeExecute(Sender: TObject);
var
  ini:TMemIniFile;
begin
  CurrentVisLoading := TVisLoading.Create(Self);
  with CurrentVisLoading do
  try
    ExceptionOnStop:=True;
    ini := TMemIniFile.Create(WaptIniFilename);
    ini.SetStrings(EdWaptInifile.Lines);
    ini.UpdateFile;

    ProgressTitle('Mise à jour index des packages');
    ProgressStep(1,8);
    runwapt('{app}\wapt-get.exe update-packages "{app}\waptserver\repository\wapt"');

    ProgressTitle('Suppression certificat TIS et copie du nouveau certificat');
    ProgressStep(2,8);
    if FileExists(WaptBaseDir+'\ssl\tranquilit.crt') then
      FileUtil.DeleteFileUTF8(WaptBaseDir+'\ssl\tranquilit.crt');
    Fileutil.CopyFile(ChangeFileExt(EdPrivateKeyFN.Text,'.crt'),WaptBaseDir+'\ssl\'+ChangeFileExt(ExtractFileNameOnly(EdPrivateKeyFN.Text),'.crt'),True);
    runwapt('{app}\wapt-get.exe update-packages "{app}\waptserver\repository\wapt"');

    ProgressTitle('Mise en place mot de passe du serveur');
    ProgressStep(3,8);
    IniWriteString(WaptBaseDir+'\waptserver\waptserver.ini' ,'Options','wapt_password',sha1.SHA1Print(sha1.SHA1String(EdPwd1.Text)));

    if CBOpenFirewall.Checked then
    begin
      ProgressTitle('Ouverture firewall pour WaptServer');
      ProgressStep(4,8);
      OpenFirewall;
    end;

    ProgressTitle('Redémarrage service waptserver');
    ProgressStep(5,8);
    if GetServiceStatusByName('','WAPTServer') in [ssRunning,ssPaused,ssPausePending,ssStartPending] then
      Sto_RedirectedExecute('cmd /C net stop waptserver');
    ProgressStep(5,8);
    Sto_RedirectedExecute('cmd /C net start waptserver');

    ProgressTitle('Redémarrage waptservice');
    ProgressStep(6,8);
    if GetServiceStatusByName('','WAPTService') in [ssRunning,ssPaused,ssPausePending,ssStartPending]  then
      Sto_RedirectedExecute('cmd /C net stop waptservice');
    Sto_RedirectedExecute('cmd /C net start waptservice');

    ProgressTitle('Enregistrement machine sur serveur');
    ProgressStep(7,8);
    runwapt('{app}\wapt-get.exe -D register');

    ProgressTitle('Mise à jour paquets locaux');
    ProgressStep(8,8);
    runwapt('{app}\wapt-get.exe -D update');

    ActNext.Execute;

  finally
    ini.Free;
    FreeAndNil(CurrentVisLoading);
  end;
end;

procedure TVisWAPTServerPostConf.BitBtn3Click(Sender: TObject);
begin
  if MessageDlg('Confirmer','Voulez-vous vraiment annuler la post-configuration du serveur WAPT ?',mtConfirmation,mbYesNoCancel,0) = mrYes then
    Close;
end;

procedure TVisWAPTServerPostConf.Button1Click(Sender: TObject);
var
  params : ISuperObject;
  waptsetupPath: string;
  done: boolean;
  ini: TIniFile;
  SORes:ISuperObject;
begin
  waptsetupPath := 'C:\Users\htouvet\AppData\Local\Temp\waptsetup.exe';
  SORes := WAPTServerJsonMultipartFilePost(edWAPTServerURL.text,'upload_waptsetup',[],'file',waptsetupPath,False,'admin','fakepassword',@IdHTTPWork);
  if SORes.S['status'] = 'OK' then
    ShowMessage('Waptsetup déposé avec succès')
  else
    ShowMessage('Erreur lors du dépôt de waptsetup: ' + SORes.S['message']);
end;

procedure TVisWAPTServerPostConf.ActManualExecute(Sender: TObject);
begin
  ActManual.Checked := not ActManual.Checked;
end;

procedure TVisWAPTServerPostConf.ActCreateKeyExecute(Sender: TObject);
begin
  EdPrivateKeyFN.Text := CreateSelfSignedCert( EdKeyName.Text,WaptBaseDir,DirectoryCert.Text,
    edCountry.Text,edLocality.Text,edOrganization.Text,edUnit.Text,edCommonName.Text,edEmail.Text);
end;

procedure TVisWAPTServerPostConf.ActCheckDNSExecute(Sender: TObject);
var
  cnames,ips : ISuperObject;
begin
  ips := Nil;
  cnames := DNSCNAMEQuery(EdWAPTServerName.Text);
  if (cnames<>Nil) and (cnames.AsArray.Length>0) then
    ips := DNSAQuery(cnames.AsArray[0].AsString)
  else
    ips := DNSAQuery(EdWAPTServerName.Text);

  if (ips<>Nil) and (ips.AsArray.Length>0) then
  begin
    EdWaptServerIP.text := ips.AsArray[0].AsString
  end
  else
  begin
    if Dialogs.MessageDlg('DNS non valide','Le nom DNS fourni n''est pas valide, voulez-vous utiliser l''adresse IP à la place ?',
        mtConfirmation,mbYesNoCancel,0) = mrYes then
    begin
      EdWAPTServerName.Text := GetLocalIP;
      EdWaptServerIP.Text:= GetLocalIP;
    end
    else
      EdWaptServerIP.text := '';
  end;

end;


function startswith(st:ISuperObject;subst:String):Boolean;
begin
  result := (st <>Nil) and (st.DataType = stString) and (pos(subst,trim(st.AsString))=1)
end;

function TVisWAPTServerPostConf.CreateWaptSetup(default_public_cert:String='';default_repo_url:String='';
          default_wapt_server:String='';destination:String='';company:String='';OnProgress:TNotifyEvent = Nil):String;
var
  OutputFile,iss_template,custom_iss,source,target : String;
  iss,new_iss,line : ISuperObject;
  wapt_base_dir,inno_fn: String;
  re : TRegexEngine;
  exitstatus:integer;
begin
    wapt_base_dir:= WaptBaseDir;
    OutputFile := '';
    iss_template := makepath([wapt_base_dir,'waptsetup','waptsetup.iss']);
    custom_iss := makepath([wapt_base_dir,'waptsetup','custom_waptsetup.iss']);
    iss := SplitLines(FileToString(iss_template));
    new_iss := TSuperObject.Create(stArray);
    for line in iss do
    begin
        if startswith(line,'#define default_repo_url') then
            new_iss.AsArray.Add(format('#define default_repo_url "%s"',[default_repo_url]))
        else if startswith(line,'#define default_wapt_server') then
            new_iss.AsArray.Add(format('#define default_wapt_server "%s"',[default_wapt_server]))
        else if startswith(line,'#define output_dir') then
            new_iss.AsArray.Add(format('#define output_dir "%s"' ,[destination]))
        else if startswith(line,'WizardImageFile=') then

        else if not startswith(line,'#define signtool') then
            new_iss.AsArray.Add(line);

        if startswith(line,'OutputBaseFilename') then
            outputfile := makepath([wapt_base_dir,'waptsetup',format('%s.exe',[Split(line.AsString,'=')[1]])]);
    end;
    source := default_public_cert;
    target := makepath([ExtractFileDir(iss_template),'..','ssl',ExtractFileName(source)]);
    if not FileUtil.CopyFile(source,target,True) then
      raise Exception.CreateFmt('Copie du certificat de %s vers %s impossible',[source,target]);
    StringToFile(custom_iss,SOUtils.Join(#13#10,new_iss));

    inno_fn :=  makepath([wapt_base_dir,'waptsetup','innosetup','ISCC.exe']);
    if not FileExists(inno_fn) then
        raise Exception.CreateFmt('Innosetup n''est pas disponible (emplacement %s), veuillez l''installer',[inno_fn]);
    Sto_RedirectedExecute(format('"%s"  %s',[inno_fn,custom_iss]),'',3600000,'','','',OnProgress);
    Result := makepath([destination,ExtractFileName(outputfile)]);
end;


procedure TVisWAPTServerPostConf.ActBuildWaptsetupExecute(Sender: TObject);
var
  params : ISuperObject;
  waptsetupPath: string;
  ini: TIniFile;
  SORes:ISuperObject;
begin
  CurrentVisLoading := TVisLoading.Create(Self);
  with CurrentVisLoading do
  try
    ExceptionOnStop:=True;
    Screen.Cursor := crHourGlass;
    ProgressTitle('Création en cours');
    Start;
    Application.ProcessMessages;
    waptsetupPath := CreateWaptSetup(fnPublicCert.FileName, edRepoUrl.Text, edWaptServerUrl1.Text,fnWaptDirectory.Directory,edOrganization.Text,@DoProgress);
    Finish;
    if FileExists(waptsetupPath) then
    try
      Start;
      ProgressTitle('Dépôt sur le serveur WAPT en cours');
      SORes := WAPTServerJsonMultipartFilePost(edWAPTServerURL1.Text,'upload_waptsetup',[],'file',waptsetupPath,False,'admin',EdPwd1.Text,@IdHTTPWork);
      Finish;
      if SORes.S['status'] = 'OK' then
        ShowMessage('waptsetup.exe créé et déposé avec succès: ' + waptsetupPath)
      else
        ShowMessage('Erreur lors du dépôt de waptsetup: ' + SORes.S['message']);
    except
      on e: Exception do
      begin
        ShowMessage('Erreur à la création du waptsetup.exe: ' + e.Message);
        Finish;
      end;
    end;
  finally
    Finish;
    Screen.Cursor := crDefault;
    FreeAndNil(CurrentVisLoading);
  end;
end;

procedure TVisWAPTServerPostConf.ActCreateKeyUpdate(Sender: TObject);
var
   TargetKeyFN:String;
begin
  TargetKeyFN := AppendPathDelim(DirectoryCert.Text)+EdKeyName.Text+'.pem';
  ActCreateKey.Enabled := (DirectoryCert.Text<>'') and (EdKeyName.Text<>'') and not FileExists(TargetKeyFN);
  if FileExists(TargetKeyFN) then
    EdPrivateKeyFN.Text := TargetKeyFN;
end;

function MakeIdent(st:String):String;
var
  i:integer;
begin
  result :='';
  for i := 1 to length(st) do
    if CharIsValidIdentifierLetter(st[i]) then
      result := Result+st[i];
end;

procedure TVisWAPTServerPostConf.EdKeyNameExit(Sender: TObject);
begin
  EdKeyName.Text:= MakeIdent(EdKeyName.Text);
end;

end.

