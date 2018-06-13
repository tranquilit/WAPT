unit uVisServerPostconf;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, LazFileUtils, LazUTF8,
  Forms, Controls, Graphics, Dialogs, ComCtrls, StdCtrls, ExtCtrls,
  Buttons, ActnList, htmlview, Readhtml, IdHTTP,
  IdComponent,uvisLoading, DefaultTranslator, LCLTranslator, LCLProc, uWaptServerRes;

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
    CBOpenFirewall: TCheckBox;
    EdPwd1: TEdit;
    EdPwd2: TEdit;
    EdWaptServerIP: TEdit;
    EdWAPTServerName: TEdit;
    HTMLViewer1: THTMLViewer;
    Label1: TLabel;
    Label2: TLabel;
    Memo7: TMemo;
    PagesControl: TPageControl;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
    Panel5: TPanel;
    panFinish: TPanel;
    pgParameters: TTabSheet;
    pgPassword: TTabSheet;
    ProgressBar1: TProgressBar;
    pgStartServices: TTabSheet;
    pgFinish: TTabSheet;
    procedure ActCheckDNSExecute(Sender: TObject);
    procedure ActManualExecute(Sender: TObject);
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
  private
    CurrentVisLoading:TVisLoading;
    procedure OpenFirewall;
    { private declarations }

  end;

var
  VisWAPTServerPostConf: TVisWAPTServerPostConf;

implementation
uses LCLIntf, Windows, waptcommon, waptwinutils, UScaleDPI, tisinifiles,
  superobject, tiscommon, tisstrings, IniFiles,DCPsha256,dcpcrypt2,DCPbase64,Math;

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

  LazGetLanguageIDs(Lang, FallbackLang);
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

  if PagesControl.ActivePage = pgFinish then
  begin
    HTMLViewer1.Parent := panFinish;
    HTMLViewer1.Align:=alClient;
  end
  else
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

procedure TVisWAPTServerPostConf.ActNextExecute(Sender: TObject);
var
  cmd,param:WideString;
begin
  if PagesControl.ActivePage<>pgFinish then
    PagesControl.ActivePageIndex := PagesControl.ActivePageIndex + 1
  else
  begin
    cmd := WaptBaseDir+'waptconsole.exe';
    param := '-c';
    if cbLaunchWaptConsoleOnExit.Checked then
      ShellExecuteW(0,'open',PWidechar(cmd),PWidechar(param),Nil,SW_SHOW);
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
  Result := '$pbkdf2-'+LowerCase(hash.GetAlgorithm)+'$'+IntToStr(count)+'$'+DCPbase64.Base64EncodeStr(salt)+'$'+DCPbase64.Base64EncodeStr(Copy(T, 1, kLen));
end;


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

function DigestToStr(Digest: array of byte): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to Length(Digest) -1 do
    Result := Result + LowerCase(IntToHex(Digest[i], 2));
end;

function GetStringHash(Source: string): string;
var
  Hash: TDCP_sha256;
  Digest: array[0..31] of Byte;
begin
  Hash := TDCP_sha256.Create(nil);
  Hash.Init;
  Hash.UpdateStr(Source);
  Hash.Final(Digest);
  Hash.Free;
  Result := DigestToStr(Digest);
end;

procedure TVisWAPTServerPostConf.actWriteConfStartServeExecute(Sender: TObject);
var
  retry:integer;
  GUID: TGuid;
  sores: ISuperobject;
  taskid:integer;
  done:boolean;
  sha: TDCP_sha256;
  dig:AnsiString;
begin
  CurrentVisLoading := TVisLoading.Create(Self);
  with CurrentVisLoading do
  try
    try
      ExceptionOnStop:=True;

      if GetServiceStatusByName('','WAPTServer') in [ssRunning,ssPaused,ssPausePending,ssStartPending] then
      try
        ProgressTitle(rsStoppingWaptServer);
        Run('cmd /C net stop waptserver');
      except
      end;

      if GetServiceStatusByName('','waptpostgresql') in [ssRunning,ssPaused,ssPausePending,ssStartPending] then
      begin
        ProgressTitle(rsStoppingPostgreSQL);
        Run('cmd /C net stop waptpostgresql');
      end;

      if GetServiceStatusByName('','waptnginx') in [ssRunning,ssPaused,ssPausePending,ssStartPending] then
      begin
        ProgressTitle(rsStoppingNGINX);
        Run('cmd /C net stop waptnginx');
      end;

      ProgressTitle(rsSettingServerPassword);
      ProgressStep(1,10);
      IniWriteString(WaptBaseDir+'\conf\waptserver.ini' ,'options','wapt_password',PBKDF2(EdPwd1.Text,MakeRandomString(5),29000,32,TDCP_sha256));
      if IniReadString(WaptBaseDir+'\conf\waptserver.ini' ,'options','server_uuid')='' then
        iniWriteString(WaptBaseDir+'\conf\waptserver.ini','options', 'server_uuid', Lowercase(Copy(GUIDToString(GUID), 2, Length(GUIDToString(GUID)) - 2)));

      ProgressTitle(rsConfigurePostgreSQL);
      ProgressStep(2,10);
      runwapt('"{app}\waptpython" "{app}\waptserver\winsetup.py" all');

      ProgressTitle(rsReplacingTIScertificate);
      ProgressStep(3,10);
      if FileExists(WaptBaseDir+'\ssl\tranquilit.crt') then
        DeleteFileUTF8(WaptBaseDir+'\ssl\tranquilit.crt');

      if CBOpenFirewall.Checked then
      begin
        ProgressTitle(rsOpeningFirewall);
        ProgressStep(4,10);
        OpenFirewall;
      end;

      ProgressTitle(rsStartingPostgreSQL);
      ProgressStep(5,10);
      Run('cmd /C net start waptpostgresql');

      ProgressTitle(rsStartingWaptServer);
      ProgressStep(6,10);
      Run('cmd /C net start waptserver');

      ProgressTitle(rsStartingNGINX);
      ProgressStep(7,10);
      Run('cmd /C net start waptnginx');

      if FileExists(WaptBaseDir+'\waptserver\mongodb\mongoexport.exe') AND
        (Dialogs.MessageDlg(rsMongoDetect,rsRunMongo2Postgresql,mtInformation,mbYesNoCancel,0) = mrYes) then
      begin
        ProgressTitle(rsMigration15);
        ProgressStep(8,10);

        runwapt('"{app}\waptpython" {app}\waptserver\waptserver_upgrade.py upgrade2postgres');

        if DirectoryExistsUTF8(WaptBaseDir+'\waptserver\mongodb') then
           fileutil.DeleteDirectory(WaptBaseDir+'\waptserver\mongodb', false);

        if DirectoryExistsUTF8(WaptBaseDir+'\waptserver\apache-win32') then
           fileutil.DeleteDirectory(WaptBaseDir+'\waptserver\apache-win32\', false);
      end;

      retry := 3;
      repeat
        ProgressTitle(rsCheckingWaptServer);
        ProgressStep(8,10);
        try
          sores := SO(IdhttpGetString('https://127.0.0.1/ping'));
        except
          sores := Nil;
        end;
        if sores<>Nil then
          ProgressTitle(sores.S['msg'])
        else
          sleep(2000);
        dec(Retry);
      until (retry<=0) or ((sores<>Nil) and sores.B['success']);
      Sleep(2000);

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

