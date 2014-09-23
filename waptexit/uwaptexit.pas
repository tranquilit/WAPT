unit uwaptexit;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, ComCtrls, ActnList, Buttons, superobject;

type

  { TVisWaptExit }

  TVisWaptExit = class(TForm)
    ActShowDetails: TAction;
    ActionList1: TActionList;
    actSkip: TAction;
    ActUpgrade: TAction;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    CheckBox1: TCheckBox;
    Image1: TImage;
    ImageList1: TImageList;
    Label1: TLabel;
    Memo1: TMemo;
    panHaut: TPanel;
    panBas: TPanel;
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
  private
    FCountDown: Integer;
    procedure SetCountDown(AValue: Integer);
    { private declarations }
  public
    { public declarations }
    upgrades,tasks,running,pending : ISuperObject;
    property CountDown:Integer read FCountDown write SetCountDown;
  end;

var
  VisWaptExit: TVisWaptExit;

implementation

uses soutils,IdHTTP,IdExceptionCore,IniFiles;
{$R *.lfm}

{ TVisWaptExit }

{
function WAPTLocalJsonGet(action: String;user:AnsiString='';password:AnsiString='';timeout:integer=1000): ISuperObject;
var
  strresult : String;
begin
  if StrLeft(action,1)<>'/' then
    action := '/'+action;
  strresult := retrieve(GetWaptLocalURL+action);
  Result := SO(strresult);
end;
}

const
  waptservice_port:integer = 8088;
  zmq_port:integer = 5000;
  allow_cancel_upgrade:Boolean = True;

function GetWaptLocalURL: String;
begin
  result := format('http://127.0.0.1:%d',[waptservice_port]);
end;

function WaptIniFilename: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0))+'wapt-get.ini';
end;


function WAPTLocalJsonGet(action: String;user:AnsiString='';password:AnsiString='';timeout:integer=1000): ISuperObject;
var
  strresult : String;
  http:TIdHTTP;
begin
  http := TIdHTTP.Create;
  try
    try
      http.ConnectTimeout:=timeout;
      if user <>'' then
      begin
        http.Request.BasicAuthentication:=True;
        http.Request.Username:=user;
        http.Request.Password:=password;
      end;

      if copy(action,length(action),1)<>'/' then
        action := '/'+action;
      strresult := http.Get(GetWaptLocalURL+action);
      Result := SO(strresult);

    except
      on E:EIdReadTimeout do Result := Nil;
    end;
  finally
    http.Free;
  end;
end;


procedure TVisWaptExit.ActUpgradeExecute(Sender: TObject);
var
  aso: ISuperObject;
begin
  Timer1.Enabled := False;
  try
    aso := WAPTLocalJsonGet('upgrade.json');
    Memo1.Text:=aso.AsJSon();
    tasks := aso['content'];
    //GridTasks.Data := tasks;
    upgrades := Nil;
    CountDown := 0;
    ActUpgrade.Caption:='Mise à jour des logiciels en cours';
    actSkip.Caption:='Stopper la mise à jour';
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
      ((pending<>Nil) and (pending.AsArray.Length>0))  then

    if allow_cancel_upgrade then
      WAPTLocalJsonGet('cancel_all_tasks.json')
    else
      Canclose := False
end;

procedure TVisWaptExit.FormCreate(Sender: TObject);
var
  ini:TIniFile;
begin
  //Load config
  ini := TIniFile.Create(WaptIniFilename);
  try
    waptservice_port := ini.ReadInteger('global','waptservice_port',waptservice_port);
    zmq_port := ini.ReadInteger('global','zmq_port',zmq_port);
    allow_cancel_upgrade := ini.ReadBool('global','allow_cancel_upgrade',allow_cancel_upgrade);
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
    aso := WAPTLocalJsonGet('checkupgrades.json','','',500);
    if aso<>Nil then
      upgrades := aso['upgrades']
    else
      upgrades := Nil;

    //check if running or pending tasks.
    aso := WAPTLocalJsonGet('tasks.json','','',10);
    if aso<>Nil then
    begin
      running := aso['running'];
      pending := aso['pending'];
    end;

    //check if upgrades
    if ((upgrades=Nil) or (upgrades.AsArray.Length = 0)) and  ((running=Nil) or (running.DataType=stNull))  and ((pending = Nil) or (pending.AsArray.Length = 0)) then
     //Système à jour
      Application.terminate
    else
    begin
      ActUpgrade.Enabled:=True;
      Memo1.Text:= Join(#13#10, upgrades);
    end;
    CountDown:=10;
    Timer1.Enabled := True;

  except
    application.Terminate;
  end;
end;

procedure TVisWaptExit.Timer1Timer(Sender: TObject);
var
  aso:ISuperObject;
begin
  timer1.Enabled:=False;
  try
    // get current tasks manager status
    aso := WAPTLocalJsonGet('tasks.json');
    if aso <> Nil then
    begin
      running := aso['running'];
      if (running<>Nil) and (running.DataType=stNull) then
        running := Nil;
      pending := aso['pending'];
      if (pending<>Nil) and (pending.AsArray.Length=0) then
        pending := Nil;
    end
    else
    begin
      running := Nil;
      pending := Nil;
    end;

    //tasks are remaining
    if (upgrades = Nil) and (
      ((running<>Nil) and (running.dataType<>stNull)) or
      ((pending<>Nil) and (pending.AsArray.Length>0)))  then
    begin
      if (running<>Nil) and (running.DataType<>stNull) then
      begin
        //ProgressBar1.Position:=running.I['progress'];
        Memo1.Lines.Text:=running.S['description']+#13#10+running.S['runstatus'];
      end;
      //GridTasks.Data:=pending;
    end;

    //No tasks and no upgrades
    if ((running=Nil) or (Running.datatype=stNull)) and ((pending=Nil) or (pending.AsArray.Length=0)) and (upgrades=Nil) then
      Close;

    //upgrades are pending, launch upgrades after timeout expired or manual action
    if (upgrades<>Nil) then
    begin
      if CountDown<=0 then
      begin
        ActUpgrade.Execute;
        //ProgressBar1.Position := 0;
      end
      else
        //ProgressBar1.Position := ProgressBar1.Position+1;
        CountDown:=CountDown-1;
    end;

  finally
    Timer1.Enabled:=True;
    Application.ProcessMessages;
  end;
end;

procedure TVisWaptExit.SetCountDown(AValue: Integer);
begin
  if FCountDown=AValue then Exit;
  FCountDown := AValue;
  if CountDown>0 then
  begin
    ActUpgrade.Caption:='Mise à jour des logiciels dans '+IntToStr(CountDown)+' sec...';
    FCountDown:=AValue;
  end
  else
    ActUpgrade.Caption:='Lancer la mise à jour des logiciels';
end;

end.

