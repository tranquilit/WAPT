unit uwaptexit;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, LazFileUtils, Forms,
  Controls, Graphics, Dialogs, StdCtrls, ExtCtrls, ActnList, Buttons,
  superobject, DefaultTranslator, ComCtrls, uWaptExitRes, sogrid;

type

  { TVisWaptExit }

  TVisWaptExit = class(TForm)
    ActShowDetails: TAction;
    ActionList1: TActionList;
    actSkip: TAction;
    ActUpgrade: TAction;
    ButNotNow: TBitBtn;
    ButUpgradeNow: TBitBtn;
    CheckBox1: TCheckBox;
    EdRunning: TEdit;
    GridPending: TSOGrid;
    CustomLogo: TImage;
    LabDontShutdown: TLabel;
    LabIntro: TLabel;
    PanButtons: TPanel;
    ImageList1: TImageList;
    MemoLog: TListBox;
    PanOut: TPanel;
    panTop: TPanel;
    PanProgress: TPanel;
    panHaut: TPanel;
    panBas: TPanel;
    ProgressBar: TProgressBar;
    Splitter1: TSplitter;
    Timer1: TTimer;
    procedure ActShowDetailsExecute(Sender: TObject);
    procedure actSkipExecute(Sender: TObject);
    procedure actSkipUpdate(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure ActUpgradeUpdate(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
    procedure OnRunNotify(Sender: TObject);
  private
    { private declarations }
    FAllowCancelUpgrade: Boolean;
    FCountDown: Integer;
    FInitialCountDown: Integer;
    FPriorities: String;
    FOnlyIfNotProcessRunning: Boolean;
    procedure SetCountDown(AValue: Integer);
    function  CheckAllowCancelUpgrade:Boolean;
    procedure SetInitialCountDown(AValue: Integer);
  public
    { public declarations }
    upgrades,tasks,running,pending : ISuperObject;
    // wait for waptservice answer in seconds
    WaptserviceTimeout: Integer;
    WAPTServiceRunning:Boolean;

    Function ShouldBeUpgraded:Boolean;
    Function CheckRunningAndPending:Boolean;
    Function WorkInProgress:Boolean;

    property AllowCancelUpgrade:Boolean read FAllowCancelUpgrade write FAllowCancelUpgrade;
    property InitialCountDown:Integer read FInitialCountDown write SetInitialCountDown;
    property CountDown:Integer read FCountDown write SetCountDown;
    property Priorities: String read FPriorities write FPriorities;
    property OnlyIfNotProcessRunning: Boolean read FOnlyIfNotProcessRunning write FOnlyIfNotProcessRunning;
  end;

var
  VisWaptExit: TVisWaptExit;

implementation

uses soutils,IniFiles,waptcommon,tisstrings, uScaleDPI,waptwinutils,tiscommon,typinfo;
{$R *.lfm}
{$ifdef ENTERPRISE }
{$R res_enterprise.rc}
{$else}
{$R res_community.rc}
{$endif}

{ TVisWaptExit }


function  TVisWaptExit.CheckAllowCancelUpgrade:Boolean;
begin
  Result := AllowCancelUpgrade and ((running=Nil) or (Running.datatype=stNull));
end;

procedure TVisWaptExit.SetInitialCountDown(AValue: Integer);
begin
  if FInitialCountDown=AValue then Exit;
  FInitialCountDown:=AValue;
end;

function GetWaptLocalURL: String;
begin
  result := format('http://127.0.0.1:%d',[waptservice_port]);
end;

function WaptIniFilename: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0))+'wapt-get.ini';
end;

procedure TVisWaptExit.ActUpgradeExecute(Sender: TObject);
var
  aso,args: ISuperObject;
  PrevTimer: Boolean;
begin
  PrevTimer:=Timer1.Enabled;
  Timer1.Enabled := False;
  CountDown := 0;
  try
    if WAPTServiceRunning then
    try
      args := TSuperObject.Create(stArray);
      if OnlyIfNotProcessRunning then
        args.AsArray.Add('only_if_not_process_running=1');
      if Priorities <> '' then
        args.AsArray.Add(Format('only_priorities=%s',[Priorities]));

      aso := WAPTLocalJsonGet('upgrade.json?'+Join('&',args),'','',WaptserviceTimeout*1000);
      if aso <> Nil then
      begin
        upgrades := Nil;
        MemoLog.Items.Text:=aso.AsJSon(True);
        tasks := aso['content'];
        pending := tasks;
        if (tasks <> Nil) and (tasks.AsArray<>Nil) then
          ProgressBar.Max:=tasks.AsArray.Length;
        ProgressBar.Position:=0;
        //GridTasks.Data := tasks;
        ActUpgrade.Caption:=rsUpdatingSoftware;
        actSkip.Caption:=rsInterruptUpdate;
        ButUpgradeNow.Visible := False;
        LabIntro.Visible := False;
        LabDontShutdown.Visible := True;
      end
    except
      // TODO: handle properly the exception..
      upgrades := Nil;
      Close;
    end
    else
      // try using direct call
      try
        //GridTasks.Data := tasks;
        upgrades := Nil;
        ActUpgrade.Caption:=rsUpdatingSoftware;
        actSkip.Caption:=rsInterruptUpdate;
        ButUpgradeNow.Visible := False;
        LabIntro.Visible := False;
        LabDontShutdown.Visible := True;
        Application.ProcessMessages;
        Run('wapt-get -D upgrade','',3600000,'','','',@OnRunNotify);
      Finally
        Close;
      end;
  finally
    if PrevTimer then
      Timer1.Enabled := True;
  end;
end;

procedure TVisWaptExit.ActUpgradeUpdate(Sender: TObject);
begin
  ActUpgrade.Enabled:= (upgrades <> Nil) and ((tasks=Nil) or (tasks.AsArray.Length=0));
end;

procedure TVisWaptExit.FormCloseQuery(Sender: TObject; var CanClose: boolean);
begin
  if Not CheckAllowCancelUpgrade and WorkInProgress then
  begin
    CanClose:=False;
    Exit;
  end;

  if WorkInProgress then
    if CheckAllowCancelUpgrade then
      WAPTLocalJsonGet('cancel_all_tasks.json','','',WaptserviceTimeout*1000)
    else
      Canclose := False
end;

procedure TVisWaptExit.FormCreate(Sender: TObject);
var
  ini:TIniFile;
begin
  if FileExists(AppendPathDelim(WaptBaseDir)+'templates\waptexit-logo.png') then
    CustomLogo.Picture.LoadFromFile(AppendPathDelim(WaptBaseDir)+'templates\waptexit-logo.png')
  else
    CustomLogo.Picture.LoadFromResourceName(HINSTANCE,'WAPT_PNG',TPortableNetworkGraphic);

  ScaleDPI(Self,96); // 96 is the DPI you designed
  ScaleImageList(ImageList1,96);
  WaptserviceTimeout := 2;

  //Load config
  ini := TIniFile.Create(WaptIniFilename);
  try
    AllowCancelUpgrade := FindCmdLineSwitch('allow_cancel_upgrade') or ini.ReadBool('global','allow_cancel_upgrade',True);
    WaptserviceTimeout := ini.ReadInteger('global','waptservice_timeout',2);
    InitialCountDown := StrToInt(GetCmdParams('waptexit_countdown',ini.ReadString('global','waptexit_countdown','10')));
    Priorities := GetCmdParams('priorities',ini.ReadString('global','upgrade_priorities',''));
    OnlyIfNotProcessRunning := FindCmdLineSwitch('only_if_not_process_running') or ini.ReadBool('global','upgrade_only_if_not_process_running',True);
  finally
    ini.Free;
  end;
end;

procedure TVisWaptExit.actSkipExecute(Sender: TObject);
begin
  Close;
end;

procedure TVisWaptExit.actSkipUpdate(Sender: TObject);
begin
  actSkip.Enabled:=CheckAllowCancelUpgrade;
end;

procedure TVisWaptExit.ActShowDetailsExecute(Sender: TObject);
begin
  panBas.Visible:=ActShowDetails.Checked;
end;

Function TVisWaptExit.ShouldBeUpgraded:Boolean;
begin
  Result := (Upgrades <> Nil) and (upgrades.AsArray <> Nil) and (upgrades.AsArray.Length>0);
end;

procedure TVisWaptExit.FormShow(Sender: TObject);
var
  aso: ISuperObject;
begin

  ActShowDetails.Checked:=False;

  aso := Nil;
  upgrades := Nil;
  tasks := Nil;
  running := Nil;
  pending := Nil;

  ActUpgrade.Enabled:=false;

  //Check if pending upgrades
  try
    if not (GetServiceStatusByName('','WAPTService') in [ssRunning])  then
      Raise Exception.Create('WAPTService is not running: '+GetEnumName(TypeInfo(TServiceState),ord(GetServiceStatusByName('','WAPTService'))));
    aso := WAPTLocalJsonGet('checkupgrades.json','','',WaptserviceTimeout*1000);
    if aso<>Nil then
    begin
      WAPTServiceRunning:=True;
      upgrades := aso['upgrades'];
      CheckRunningAndPending;
      GridPending.data := pending;
    end;
  except
    on E:Exception do
    begin
      // timeout on waptservice, trying direct call...
      WAPTServiceRunning:=False;
      try
        aso := SO(Run('wapt-get -j check-upgrades','',10000));
        if aso<>Nil then
          upgrades := aso['result.upgrades'];
      except
        upgrades := Nil;
      end;
    end;
  end;

  //check if upgrades
  if not ShouldBeUpgraded and not WorkInProgress then
    Application.terminate
  else
  begin
    ActUpgrade.Enabled := ShouldBeUpgraded;
    if ShouldBeUpgraded then
    begin
      MemoLog.Items.Text:= Join(#13#10, upgrades);
      LabIntro.Caption := Format(rsUpdatesAvailable,[upgrades.AsArray.Length]);
    end
    else
    if running <> Nil then
      LabIntro.Caption := UTF8Encode(running.S['description']);
  end;

  if CheckAllowCancelUpgrade then
    CountDown:=InitialCountDown
  else
    CountDown:=0;
  Timer1.Enabled := True;
end;

Function TVisWaptExit.WorkInProgress:Boolean;
begin
  Result :=
      ((running<>Nil) and (running.dataType<>stNull)) or
      ((pending<>Nil) and (pending.dataType=stArray) and (pending.AsArray.Length>0))
end;

Function TVisWaptExit.CheckRunningAndPending:Boolean;
var
  aso:ISuperObject;
begin
  If WAPTServiceRunning then
  begin
    // get current tasks manager status
    aso := WAPTLocalJsonGet('tasks.json','','',WaptserviceTimeout*1000);
    if aso <> Nil then
    begin
      running := aso['running'];
      if (running<>Nil) and (running.DataType=stNull) then
        running := Nil;
      pending := aso['pending'];
      if (pending<>Nil) and (pending.DataType=stArray) and (pending.AsArray.Length=0) then
        pending := Nil;
      Result := True;
    end
    else
    begin
      running := Nil;
      pending := Nil;
      Result := False;
    end
  end
  else
  begin
    running := Nil;
    pending := Nil;
    Result := False;
  end
end;

procedure TVisWaptExit.Timer1Timer(Sender: TObject);
begin
  timer1.Enabled:=False;
  try
    CheckRunningAndPending;

    // Updates UI
    GridPending.Data := pending;
    if (running<>Nil) then
    begin
      EdRunning.Text := UTF8Encode(running.S['description']);
      MemoLog.Items.Text := UTF8Encode(running.S['runstatus']);
    end;
    Application.ProcessMessages;

    //No tasks and no upgrades
    if not WorkInProgress and not ShouldBeUpgraded then
      Close;

    if (pending<>Nil) then
      ProgressBar.Position:=ProgressBar.Max - pending.AsArray.Length;

    //some upgrades are pending, launch upgrades after timeout expired or manual action
    if ShouldBeUpgraded and (CountDown<=0) then
      ActUpgrade.Execute;

  finally
    CountDown := CountDown-1;
    Application.ProcessMessages;
    Timer1.Enabled := True;
  end;
end;

procedure TVisWaptExit.OnRunNotify(Sender: TObject);
begin
  EdRunning.Text:= rsUpgradeRunning;
  Application.ProcessMessages;
end;

procedure TVisWaptExit.SetCountDown(AValue: Integer);
begin
  if FCountDown=AValue then Exit;
  FCountDown := AValue;
  if CountDown>0 then
  begin
    ActUpgrade.Caption:=Format(rsSoftwareUpdateIn,[IntToStr(FCountDown)]);
    FCountDown:=AValue;
  end
  else
    ActUpgrade.Caption:=rsLaunchSoftwareUpdate;
end;

end.

