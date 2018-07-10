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
    FCountDown: Integer;
    FInitialCountDown: Integer;
    procedure SetCountDown(AValue: Integer);
    { private declarations }
    function  allow_cancel_upgrade:Boolean;
    procedure SetInitialCountDown(AValue: Integer);
  public
    { public declarations }
    upgrades,tasks,running,pending : ISuperObject;
    // wait for waptservice answer in seconds
    waptservice_timeout: Integer;
    WAPTServiceRunning:Boolean;

    property InitialCountDown:Integer read FInitialCountDown write SetInitialCountDown;
    property CountDown:Integer read FCountDown write SetCountDown;
  end;

var
  VisWaptExit: TVisWaptExit;

implementation

uses soutils,IniFiles,waptcommon,uScaleDPI,waptwinutils,tiscommon,typinfo;
{$R *.lfm}
{$ifdef ENTERPRISE }
{$R res_enterprise.rc}
{$else}
{$R res_community.rc}
{$endif}

{ TVisWaptExit }

const FAllow_cancel_upgrade:Boolean = True;

function  TVisWaptExit.allow_cancel_upgrade:Boolean;
begin
  Result := FAllow_cancel_upgrade and ((running=Nil) or (Running.datatype=stNull));
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
  aso: ISuperObject;
begin
  Timer1.Enabled := False;
  try
    if WAPTServiceRunning then
    try
      aso := WAPTLocalJsonGet('upgrade.json','','',waptservice_timeout*1000);
      if aso <> Nil then
      begin
        MemoLog.Items.Text:=aso.AsJSon();
        tasks := aso['content'];
        pending := tasks;
        if (tasks <> Nil) and (tasks.AsArray<>Nil) then
          ProgressBar.Max:=tasks.AsArray.Length;
        ProgressBar.Position:=0;
        //GridTasks.Data := tasks;
        upgrades := Nil;
        CountDown := 0;
        ActUpgrade.Caption:=rsUpdatingSoftware;
        actSkip.Caption:=rsInterruptUpdate;
        ButUpgradeNow.Visible := False;
        LabIntro.Visible := False;
        LabDontShutdown.Visible := True;
      end
    except
      // TODO: handle properly the exception..
      Close;
    end
    else
      // try using direct call
      try
        //GridTasks.Data := tasks;
        upgrades := Nil;
        CountDown := 0;
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
    Timer1.Enabled := True;
  end;
end;

procedure TVisWaptExit.ActUpgradeUpdate(Sender: TObject);
begin
  ActUpgrade.Enabled:=(tasks=Nil) or (tasks.AsArray.Length=0);
end;

procedure TVisWaptExit.FormCloseQuery(Sender: TObject; var CanClose: boolean);
begin
  if  Not allow_cancel_upgrade and
       ( ((upgrades<>Nil) and (upgrades.AsArray.Length>0)) or
         ((running<>Nil) and (running.dataType<>stNull)) or
         ((pending<>Nil) and (pending.AsArray.Length>0))
       ) then
  begin
      CanClose:=False;
      Exit;
  end;

  if ((running<>Nil) and (running.dataType<>stNull)) or
      ((pending<>Nil) and (pending.dataType=stArray) and (pending.AsArray.Length>0))  then

    if allow_cancel_upgrade then
      WAPTLocalJsonGet('cancel_all_tasks.json','','',waptservice_timeout*1000)
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
  waptservice_timeout := 2;

  //Load config
  ini := TIniFile.Create(WaptIniFilename);
  try
    Fallow_cancel_upgrade := FindCmdLineSwitch('allow_cancel_upgrade') or ini.ReadBool('global','allow_cancel_upgrade',True);
    waptservice_timeout := ini.ReadInteger('global','waptservice_timeout',2);
    InitialCountDown := StrToInt(GetCmdParams('waptexit_countdown',ini.ReadString('global','waptexit_countdown','10')));
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
  actSkip.Enabled:=allow_cancel_upgrade;
end;

procedure TVisWaptExit.ActShowDetailsExecute(Sender: TObject);
begin
  panBas.Visible:=ActShowDetails.Checked;
end;

procedure TVisWaptExit.FormShow(Sender: TObject);
var
  aso: ISuperObject;
  TasksCount:Integer;
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
    aso := WAPTLocalJsonGet('checkupgrades.json','','',waptservice_timeout*1000);
    if aso<>Nil then
    begin
      WAPTServiceRunning:=True;
      upgrades := aso['upgrades'];
      //check if running or pending tasks.
      aso := WAPTLocalJsonGet('tasks.json','','',waptservice_timeout*1000);
      if aso<>Nil then
      begin
        running := aso['running'];;
        pending := aso['pending'];
        GridPending.data := pending;
      end;
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
  if ((upgrades=Nil) or (upgrades.AsArray = Nil) or (upgrades.AsArray.Length = 0)) and  ((running=Nil) or (running.DataType=stNull))  and ((pending = Nil) or (pending.AsArray.Length = 0)) then
   //Système à jour ou erreur
    Application.terminate
  else
  begin
    ActUpgrade.Enabled:=True;
    MemoLog.Items.Text:= Join(#13#10, upgrades);
    LabIntro.Caption:=Format(rsUpdatesAvailable,[upgrades.AsArray.Length]);
  end;

  if allow_cancel_upgrade then
    CountDown:=InitialCountDown
  else
    CountDown:=0;
  Timer1.Enabled := True;
end;

procedure TVisWaptExit.Timer1Timer(Sender: TObject);
var
  aso:ISuperObject;
begin
  timer1.Enabled:=False;
  try
    If WAPTServiceRunning then
    begin
      // get current tasks manager status
      aso := WAPTLocalJsonGet('tasks.json','','',waptservice_timeout*1000);
      if aso <> Nil then
      begin
        running := aso['running'];
        if (running<>Nil) and (running.DataType=stNull) then
          running := Nil;
        pending := aso['pending'];
        if (pending<>Nil) and (pending.DataType=stArray) and (pending.AsArray.Length=0) then
          pending := Nil;

        //tasks are remaining
        if (upgrades = Nil) and (
          ((running<>Nil) and (running.dataType<>stNull)) or
          ((pending<>Nil) and (pending.AsArray.Length>0)))
        then
        begin
          GridPending.Data := pending;
          if (running<>Nil) and (running.DataType<>stNull) then
          begin
            EdRunning.Text := UTF8Encode(running.S['description']);
            MemoLog.Items.Text := UTF8Encode(running.S['runstatus']);
          end;
        end;
      end
      else
      begin
        running := Nil;
        pending := Nil;
      end;
    end
    else
    begin
      running := Nil;
      pending := Nil;
    end;

    //No tasks and no upgrades
    if ((running=Nil) or (Running.datatype=stNull)) and ((pending=Nil) or (pending.AsArray.Length=0)) and (upgrades=Nil) then
      Close;

    if (pending<>Nil) then
      ProgressBar.Position:=ProgressBar.Max - pending.AsArray.Length;

    //upgrades are pending, launch upgrades after timeout expired or manual action
    if (upgrades<>Nil) then
    begin
      if CountDown<=0 then
        ActUpgrade.Execute
      else
        CountDown:=CountDown-1;
    end;
  finally
    Timer1.Enabled:=True;
    Application.ProcessMessages;
  end;
end;

procedure TVisWaptExit.OnRunNotify(Sender: TObject);
begin
  EdRunning.Text:= 'Upgrade running...';
  Application.ProcessMessages;
end;

procedure TVisWaptExit.SetCountDown(AValue: Integer);
begin
  if FCountDown=AValue then Exit;
  FCountDown := AValue;
  if CountDown>0 then
  begin
    ActUpgrade.Caption:=Format(rsSoftwareUpdateIn,[IntToStr(CountDown)]);
    FCountDown:=AValue;
  end
  else
    ActUpgrade.Caption:=rsLaunchSoftwareUpdate;
end;

end.

