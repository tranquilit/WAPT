unit uVisServerPostconf;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, IpHtml, Ipfilebroker, RichView, vsVisualSynapse,
  RLRichText, Forms, Controls, Graphics, Dialogs, ComCtrls, StdCtrls, ExtCtrls,
  Buttons, ActnList, EditBtn, htmlview, Readhtml, Htmlsubs;

type

  { TVisWAPTServerPostConf }

  TVisWAPTServerPostConf = class(TForm)
    ActCheckDNS: TAction;
    ActCreateKey: TAction;
    ActCancel: TAction;
    actWriteConfStartServe: TAction;
    ActManual: TAction;
    ActNext: TAction;
    actPrevious: TAction;
    ActionList1: TActionList;
    ButPrevious: TBitBtn;
    ButNext: TBitBtn;
    BitBtn3: TBitBtn;
    BitBtn4: TBitBtn;
    BitBtn5: TBitBtn;
    BitBtn6: TBitBtn;
    cbLaunchWaptConsoleOnExit: TCheckBox;
    cbManualURL: TCheckBox;
    CBOpenFirewall: TCheckBox;
    DirectoryCert: TDirectoryEdit;
    edCommonName: TEdit;
    edCountry: TEdit;
    EdSourcesRoot: TLabeledEdit;
    edEmail: TEdit;
    EdPwd1: TEdit;
    EdPrivateKeyFN: TEdit;
    edLocality: TEdit;
    edOrganization: TEdit;
    EdOrgName: TEdit;
    EdPwd2: TEdit;
    edUnit: TEdit;
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
    Memo6: TMemo;
    PagesControl: TPageControl;
    Panel1: TPanel;
    pgParameters: TTabSheet;
    pgPassword: TTabSheet;
    Shape1: TShape;
    StaticText1: TStaticText;
    pgStartServices: TTabSheet;
    pgDevparam: TTabSheet;
    pgPrivateKey: TTabSheet;
    pgFinish: TTabSheet;
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
    procedure EdOrgNameExit(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure HTMLViewer1HotSpotClick(Sender: TObject; const SRC: string;
      var Handled: boolean);
    procedure PagesControlChange(Sender: TObject);
  private
    procedure OpenFirewall;
    { private declarations }
  public
    { public declarations }
  end;

var
  VisWAPTServerPostConf: TVisWAPTServerPostConf;

implementation
uses LCLIntf, Windows,WaptCommon,tisinifiles,superobject,
    tiscommon,tisstrings,IniFiles,UnitRedirect,uvisLoading,sha1;
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
  if GetServiceStatusByName('','WAPTServer') = ssRunning then
    Sto_RedirectedExecute('cmd /C net stop waptserver');

  EdWAPTServerName.Text:=LowerCase(GetComputerName)+'.'+GetDNSDomain;
  if IniHasKey(WaptIniFilename,'global','default_package_prefix') then
    EdDefaultPrefix.Text:=IniReadString(WaptIniFilename,'global','default_package_prefix');
  if IniHasKey(WaptIniFilename,'global','default_sources_root') then
    EdSourcesRoot.Text:=IniReadString(WaptIniFilename,'global','default_sources_root');
  if IniHasKey(WaptIniFilename,'global','templates_repo_url') then
    EdTemplatesRepoURL.Text:=IniReadString(WaptIniFilename,'global','templates_repo_url');
  PagesControlChange(Self);
end;

procedure TVisWAPTServerPostConf.HTMLViewer1HotSpotClick(Sender: TObject;
  const SRC: string; var Handled: boolean);
begin
  OpenURL(SRC);
  Handled:=True;
end;

procedure TVisWAPTServerPostConf.PagesControlChange(Sender: TObject);
var
  ini:TMemIniFile;

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
    ini.GetStrings(EdWaptInifile.Lines);
  finally
    ini.Free;
  end;
  if PagesControl.ActivePage = pgFinish then
  begin
    HTMLViewer1.Parent := pgFinish;
    HTMLViewer1.Align:=alClient;
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
    output := Sto_RedirectedExecute(format('netsh advfirewall firewall show rule name="waptserver %d"',[waptserver_port]));
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
  with TVisLoading.Create(Self) do
  try
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


    ProgressTitle('Mise en place mot de passe server');
    ProgressStep(3,8);
    IniWriteString(WaptBaseDir+'\waptserver\waptserver.ini' ,'Options','wapt_password',sha1.SHA1Print(sha1.SHA1String(EdPwd1.Text)));

    ProgressTitle('Ouverture firewall pour WaptServer');
    ProgressStep(4,8);
    OpenFirewall;

    ProgressTitle('Redémarrage waptserver');
    ProgressStep(5,8);
    try
      if GetServiceStatusByName('','WAPTServer') = ssRunning then
        Sto_RedirectedExecute('cmd /C net stop waptserver');
    except
    end;
    Sto_RedirectedExecute('cmd /C net start waptserver');

    ProgressTitle('Redémarrage waptservice');
    ProgressStep(6,8);
    try
      if GetServiceStatusByName('','WAPTService') = ssRunning then
        Sto_RedirectedExecute('cmd /C net stop waptservice');
    except
    end;
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
    Free;
  end;
end;

procedure TVisWAPTServerPostConf.BitBtn3Click(Sender: TObject);
begin
  if MessageDlg('Confirmer','Voulez-vous vraiment annuler la post-configuration du serveur WAPT ?',mtConfirmation,mbYesNoCancel,0) = mrYes then
    Close;
end;

procedure TVisWAPTServerPostConf.Button1Click(Sender: TObject);
begin
  showmessage(Sto_RedirectedExecute('netsh firewall show portopening'));
  showmessage(Sto_RedirectedExecute(format('netsh.exe firewall add portopening name="waptserver %d" port=%d protocol=TCP',[waptserver_port,waptserver_port])));
end;

procedure TVisWAPTServerPostConf.ActManualExecute(Sender: TObject);
begin
  ActManual.Checked := not ActManual.Checked;
end;

procedure TVisWAPTServerPostConf.ActCreateKeyExecute(Sender: TObject);
begin
  EdPrivateKeyFN.Text := CreateSelfSignedCert( EdOrgName.Text,WaptBaseDir,DirectoryCert.Text,
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

procedure TVisWAPTServerPostConf.ActCreateKeyUpdate(Sender: TObject);
var
   TargetKeyFN:String;
begin
  TargetKeyFN := AppendPathDelim(DirectoryCert.Text)+EdOrgName.Text+'.pem';
  ActCreateKey.Enabled := (DirectoryCert.Text<>'') and (EdOrgName.Text<>'') and not FileExists(TargetKeyFN);
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

procedure TVisWAPTServerPostConf.EdOrgNameExit(Sender: TObject);
begin
  EdOrgName.Text:= MakeIdent(EdOrgName.Text);
end;

end.

