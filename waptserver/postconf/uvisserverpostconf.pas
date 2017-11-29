unit uVisServerPostconf;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil,
  Forms, Controls, Graphics, Dialogs, ComCtrls, StdCtrls, ExtCtrls,
  Buttons, ActnList, htmlview, Readhtml, IdHTTP,
  IdComponent,uvisLoading, DefaultTranslator, LCLProc, uWaptServerRes, types;

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
    BitBtn4: TBitBtn;
    BitBtn3: TBitBtn;
    BitBtn6: TBitBtn;
    ButNext: TBitBtn;
    ButPrevious: TBitBtn;
    cbLaunchWaptConsoleOnExit: TCheckBox;
    cbManualURL: TCheckBox;
    CBOpenFirewall: TCheckBox;
    EdPwd1: TEdit;
    EdPwd2: TEdit;
    EdWaptServerIP: TEdit;
    EdWAPTServerName: TEdit;
    HTMLViewer1: THTMLViewer;
    edWAPTRepoURL: TLabeledEdit;
    edWAPTServerURL: TLabeledEdit;
    EdWaptInifile: TMemo;
    Label1: TLabel;
    Label2: TLabel;
    Memo7: TMemo;
    PagesControl: TPageControl;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
    Panel4: TPanel;
    Panel5: TPanel;
    panFinish: TPanel;
    pgParameters: TTabSheet;
    pgPassword: TTabSheet;
    ProgressBar1: TProgressBar;
    pgStartServices: TTabSheet;
    pgFinish: TTabSheet;
    procedure ActCheckDNSExecute(Sender: TObject);
    procedure ActManualExecute(Sender: TObject);
    procedure ActManualUpdate(Sender: TObject);
    procedure ActNextExecute(Sender: TObject);
    procedure ActNextUpdate(Sender: TObject);
    procedure actPreviousExecute(Sender: TObject);
    procedure actPreviousUpdate(Sender: TObject);
    procedure actWriteConfStartServeExecute(Sender: TObject);
    procedure BitBtn3Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure HTMLViewer1HotSpotClick(Sender: TObject; const SRC: string;
      var Handled: boolean);
    procedure IdHTTPWork(ASender: TObject; AWorkMode: TWorkMode;
      AWorkCount: Int64);
    procedure PagesControlChange(Sender: TObject);
    procedure pgParametersContextPopup(Sender: TObject; MousePos: TPoint;
      var Handled: Boolean);
  private
    CurrentVisLoading:TVisLoading;
    procedure OpenFirewall;
    { private declarations }

  end;

var
  VisWAPTServerPostConf: TVisWAPTServerPostConf;

implementation
uses LCLIntf, Windows, waptcommon, waptwinutils, UScaleDPI, tisinifiles,
  superobject, tiscommon, tisstrings, IniFiles;

{$R *.lfm}

{ TVisWAPTServerPostConf }

procedure TVisWAPTServerPostConf.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96);
  HTMLViewer1.DefFontSize := ScaleY(HTMLViewer1.DefFontSize,96);
  ReadWaptConfig(WaptBaseDir+'wapt-get.ini');
  PagesControl.ShowTabs:=False;
  PagesControl.ActivePageIndex:=0;
end;

procedure TVisWAPTServerPostConf.FormShow(Sender: TObject);
begin
  if GetServiceStatusByName('','WAPTServer') in  [ssRunning,ssPaused,ssPausePending,ssStartPending] then
    Run('cmd /C net stop waptserver');

  EdWAPTServerName.Text:=LowerCase(GetComputerName)+'.'+GetDNSDomain;
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

function GetString(const Index: integer) : string;
var
  buffer : array[0..8191] of char;
  ls : integer;
begin
  Result := '';
  ls := LoadString(hInstance,
                   Index,
                   buffer,
                   sizeof(buffer));
  if ls <> 0 then Result := buffer;
end;



procedure TVisWAPTServerPostConf.PagesControlChange(Sender: TObject);
const
  PAGES_INDEX_STEP =  100; // cf. languages.rc
  PAGES_EN_OFFSET =		0;
  PAGES_FR_OFFSET =		1;
  PAGES_DE_OFFSET =		2;
var
  ini:TIniFile;
  Page: TMemoryStream;
  PageContent: AnsiString;
  Lang, FallbackLang: String;
  i, LangOffset: Integer;
begin
  { XXX This is not what I'd call clean language detection... }

  LCLGetLanguageIDs(Lang, FallbackLang);
  LangOffset := PAGES_EN_OFFSET;
  if FallbackLang = 'fr' then
    LangOffset := PAGES_FR_OFFSET
  else if FallbackLang = 'de' then
    LangOffset := PAGES_DE_OFFSET;

  for i := 1 to ParamCount-1 do
    if ((ParamStr(i) = '-l') or (ParamStr(i) = '--lang')) and (i+1 <> ParamCount-1) then
    begin
      if ParamStr(i+1) = 'de' then
         LangOffset := PAGES_DE_OFFSET
      else
      if ParamStr(i+1) = 'fr' then
         LangOffset := PAGES_FR_OFFSET
      else
        LangOffset := PAGES_EN_OFFSET;
    end;

  PageContent := GetString(langOffset + PagesControl.ActivePageIndex * PAGES_INDEX_STEP);
  Page := TMemoryStream.Create;
  Page.WriteAnsiString(PageContent);
  HTMLViewer1.LoadFromStream(Page);
  Page.Free;

  if PagesControl.ActivePage = pgStartServices then
  try
    ini := TMemIniFile.Create(WaptIniFilename);
    ini.WriteString('global','repo_url',edWAPTRepoURL.Text);
    ini.WriteString('global','wapt_server',edWAPTServerURL.Text);
    ini.WriteString('global','verify_cert','0');
    ini.WriteString('wapt-templates','verify_cert','1');
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
end;

procedure TVisWAPTServerPostConf.pgParametersContextPopup(Sender: TObject;
  MousePos: TPoint; var Handled: Boolean);
begin

end;

procedure TVisWAPTServerPostConf.OpenFirewall;
var
   output : String;
begin
  if GetServiceStatusByName('','SharedAccess') = ssRunning then
  begin
    output := Run('netsh firewall show portopening');
    if pos('waptserver 80',output)<=0 then
      Run(format('netsh.exe firewall add portopening name="waptserver %d" port=%d protocol=TCP',[waptserver_port,waptserver_port]));
    if pos('waptserver 443',output)<=0 then
      Run(format('netsh.exe firewall add portopening name="waptserver %d" port=%d protocol=TCP',[waptserver_sslport,waptserver_sslport]));
  end
  else if GetServiceStatusByName('','MpsSvc') = ssRunning then
  begin
    output:='';
    try
      output := Run(format('netsh advfirewall firewall show rule name="waptserver %d"',[waptserver_port]));
    except
    end;
    if pos('waptserver 80',output)<=0 then
      output := Run(format('netsh advfirewall firewall add rule name="waptserver %d" dir=in localport=%d protocol=TCP action=allow',[waptserver_port,waptserver_port]));
    try
      output := Run(format('netsh advfirewall firewall show rule name="waptserver %d"',[waptserver_sslport]));
    except
    end;
    if pos('waptserver 443',output)<=0 then
      output := Run(format('netsh advfirewall firewall add rule name="waptserver %d" dir=in localport=%d protocol=TCP action=allow',[waptserver_sslport,waptserver_sslport]));
  end;
end;

procedure TVisWAPTServerPostConf.ActManualUpdate(Sender: TObject);
begin
  if not ActManual.Checked then
  begin
    edWAPTRepoURL.Enabled := False;
    edWAPTServerURL.Enabled := False;
    edWAPTRepoURL.Text := Format('https://%s/wapt',[EdWAPTServerName.Text]);
    edWAPTServerURL.Text := Format('https://%s',[EdWAPTServerName.Text]);
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
  else if PagesControl.ActivePage = pgStartServices then
    ActNext.Enabled := GetServiceStatusByName('','waptserver') = ssRunning
  else
    ActNext.Enabled := PagesControl.ActivePageIndex<=PagesControl.PageCount-1;
  if PagesControl.ActivePageIndex=PagesControl.PageCount-1 then
    ActNext.Caption:= rsWaptSetupDone
  else
    ActNext.Caption:=rsWaptSetupnext;
end;

procedure TVisWAPTServerPostConf.actPreviousExecute(Sender: TObject);
begin
  PagesControl.ActivePageIndex := PagesControl.ActivePageIndex - 1;
end;

procedure TVisWAPTServerPostConf.actPreviousUpdate(Sender: TObject);
begin
  actPrevious.Enabled:=(PagesControl.ActivePageIndex>0) and (PagesControl.ActivePageIndex<=PagesControl.PageCount-1);
end;

function runwapt(cmd:String):String;
begin
  StrReplace(cmd,'{app}',WaptBaseDir,[rfReplaceAll]);
  result := Run(cmd);
end;


{
function RPad(x: string; c: Char; s: Integer): string;
var
  i: Integer;
begin
  Result := x;
  if Length(x) < s then
    for i := 1 to s-Length(x) do
      Result := Result + c;
end;

function XorBlock(s, x: ansistring): ansistring; inline;
var
  i: Integer;
begin
  SetLength(Result, Length(s));
  for i := 1 to Length(s) do
    Result[i] := Char(Byte(s[i]) xor Byte(x[i]));
end;

function CalcDigest(text: string; dig: TDCP_hashclass): string;
var
  x: TDCP_hash;
begin
  x := dig.Create(nil);
  try
    x.Init;
    x.UpdateStr(text);
    SetLength(Result, x.GetHashSize div 8);
    x.Final(Result[1]);
  finally
    x.Free;
  end;
end;

function CalcHMAC(message, key: string; hash: TDCP_hashclass): string;
const
  blocksize = 64;
begin
  // Definition RFC 2104
  if Length(key) > blocksize then
    key := CalcDigest(key, hash);
  key := RPad(key, #0, blocksize);

  Result := CalcDigest(XorBlock(key, RPad('', #$36, blocksize)) + message, hash);
  Result := CalcDigest(XorBlock(key, RPad('', #$5c, blocksize)) + result, hash);
end;

function PBKDF1(pass, salt: ansistring; count: Integer; hash: TDCP_hashclass): ansistring;
var
  i: Integer;
begin
  Result := pass+salt;
  for i := 0 to count-1 do
    Result := CalcDigest(Result, hash);
end;


function PBKDF2(pass, salt: ansistring; count, kLen: Integer; hash: TDCP_hashclass): ansistring;

  function IntX(i: Integer): ansistring; inline;
  begin
    Result := Char(i shr 24) + Char(i shr 16) + Char(i shr 8) + Char(i);
  end;

var
  D, I, J: Integer;
  T, F, U: ansistring;
begin
  T := '';
  D := Ceil(kLen / (hash.GetHashSize div 8));
  for i := 1 to D do
  begin
    F := CalcHMAC(salt + IntX(i), pass, hash);
    U := F;
    for j := 2 to count do
    begin
      U := CalcHMAC(U, pass, hash);
      F := XorBlock(F, U);
    end;
    T := T + F;
  end;
  Result := Copy(T, 1, kLen);
end;
}

function MakeRandomString(const ALength: Integer;
                          const ACharSequence: String = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'): String;
var
  C1, sequence_length: Integer;
begin
  sequence_length := Length(ACharSequence);
  SetLength(result, ALength);

  for C1 := 1 to ALength do
    result[C1] := ACharSequence[Random(sequence_length) + 1];
end;

procedure TVisWAPTServerPostConf.actWriteConfStartServeExecute(Sender: TObject);
var
  retry:integer;
  GUID: TGuid;
  sores: ISuperobject;
  taskid:integer;
  done:boolean;
begin
  CurrentVisLoading := TVisLoading.Create(Self);
  with CurrentVisLoading do
  try
    try
      ExceptionOnStop:=True;
      if GetServiceStatusByName('','WAPTService') in [ssRunning,ssPaused,ssPausePending,ssStartPending]  then
      begin
        ProgressTitle(rsWaptServiceStopping);
        Run('cmd /C net stop waptservice');
      end;
      if GetServiceStatusByName('','WAPTServer') in [ssRunning,ssPaused,ssPausePending,ssStartPending] then
      begin
        ProgressTitle(rsWaptServiceStopping);
        Run('cmd /C net stop waptserver');
      end;


      if IniReadString(WaptBaseDir+'\conf\waptserver.ini' ,'options','server_uuid')='' then
        iniWriteString(WaptBaseDir+'\conf\waptserver.ini','options', 'server_uuid', Lowercase(Copy(GUIDToString(GUID), 2, Length(GUIDToString(GUID)) - 2)));

      ProgressTitle(rsUpdatingPackageIndex);
      ProgressStep(1,10);
      runwapt('{app}\wapt-get.exe update-packages "{app}\waptserver\repository\wapt"');

      ProgressTitle(rsConfigurePostgreSQL);
      ProgressStep(2,10);
      runwapt('{app}\waptpython {app}\waptserver\waptserver_winsetup.py all');


      ProgressTitle(rsReplacingTIScertificate);
      ProgressStep(3,10);
      if FileExists(WaptBaseDir+'\ssl\tranquilit.crt') then
        FileUtil.DeleteFileUTF8(WaptBaseDir+'\ssl\tranquilit.crt');

      ProgressTitle(rsSettingServerPassword);
      ProgressStep(4,10);

      IniWriteString(WaptBaseDir+'\conf\waptserver.ini' ,'options','wapt_password',
        Run(AppendPathDelim(WaptBaseDir)+'waptpython.exe -c "from passlib.hash import pbkdf2_sha256; print(pbkdf2_sha256.hash('''+EdPwd1.Text+'''))"')
        );

      if CBOpenFirewall.Checked then
      begin
        ProgressTitle(rsOpeningFirewall);
        ProgressStep(4,10);
        OpenFirewall;
      end;

      // reread config fir waptcommon
      WaptCommon.ReadWaptConfig(WaptIniFilename);

      ProgressStep(5,10);
      ProgressTitle(rsStartingPostgreSQL);
      Run('cmd /C net start waptpostgresql');
      ProgressTitle(rsStartingWaptServer);
      Run('cmd /C net start waptserver');
      ProgressTitle(rsStartingNGINX);
      Run('cmd /C net start waptnginx');

      retry := 3;
      repeat
        sores := WAPTServerJsonGet('ping',[],'GET',6000);
        if sores<>Nil then
          ProgressTitle(sores.S['msg'])
        else
          sleep(2000);
        dec(Retry);
      until (retry<=0) or((sores<>Nil) and sores.B['success']);
      Sleep(2000);

      if GetServiceStatusByName('','WAPTService') <> ssUnknown then
      begin
        if GetServiceStatusByName('','WAPTService') in [ssStopped]  then
        begin
		        ProgressTitle(rsRestartingWaptService);
		        ProgressStep(6,8);
		        Run('cmd /C net start waptservice');
        end;
		        retry := 3;
		        repeat
		          sores := WAPTLocalJsonGet('runstatus','','',5000);
		          if sores<>Nil then
		            ProgressTitle(sores.S['0.value'])
		          else
		            sleep(2000);
		          dec(Retry);
		        until (retry<=0) or (sores<>Nil);

		        ProgressTitle(rsRegisteringHostOnServer);
		        retry := 3;
		        taskid:=-1;
		        repeat
		          sores := WAPTLocalJsonGet('update.json?notify_server=1','','',5000);
		          if sores<>Nil then
		          begin
		            ProgressTitle(sores.S['description']);
		            taskid := sores.I['id'];
		          end;
		          if not taskid<0 then
		            Sleep(2000);
		          dec(Retry);
		        until (retry<=0) or (taskid>=0);

		        ProgressTitle(rsUpdatingLocalPackages);
		        repeat
		          sores := WAPTLocalJsonGet('task.json?id='+inttostr(taskid),'','',5000);
		          if sores<>Nil then
		          begin
		            ProgressTitle(sores.S['summary']);
		            done := sores.S['finish_date'] <> '';
		          end;
		          if not done then
		            Sleep(2000);
		          dec(Retry);
		        until (retry<=0) or done;
		        ProgressStep(8,8);
		        //runwapt('{app}\wapt-get.exe -D update');
		        //ProgressTitle(WAPTLocalJsonGet('update.json?notify_server=1','','',5000).S['description']);
      end;
      ActNext.Execute;


    except
      on E:Exception do
        Dialogs.MessageDlg('Error','Error during post-config:'#13#10+E.Message,mtError,mbOKCancel,'');
    end;
  finally
    FreeAndNil(CurrentVisLoading);
  end;
end;

procedure TVisWAPTServerPostConf.BitBtn3Click(Sender: TObject);
begin
  if MessageDlg(rsConfirm,rsConfirmCancelPostConfig,mtConfirmation,mbYesNoCancel,0) = mrYes then
    Close;
end;

procedure TVisWAPTServerPostConf.ActManualExecute(Sender: TObject);
begin
  ActManual.Checked := not ActManual.Checked;
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
    if Dialogs.MessageDlg(rsInvalidDNS,rsInvalidDNSfallback,
        mtConfirmation,mbYesNoCancel,0) = mrYes then
    begin
      EdWAPTServerName.Text := GetLocalIP;
      EdWaptServerIP.Text:= GetLocalIP;
    end
    else
      EdWaptServerIP.text := '';
  end;

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


end.

