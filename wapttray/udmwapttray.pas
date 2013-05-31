unit uDMWAPTTray;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, ExtCtrls, Menus, ActnList, Controls,uniqueinstance;

type

  { TDMWaptTray }
  TDMWaptTray = class(TDataModule)
    ActForceRegisterComputer: TAction;
    ActConfigure: TAction;
    ActLaunchGui: TAction;
    ActionList1: TActionList;
    ActQuit: TAction;
    ActShowMain: TAction;
    ActShowStatus: TAction;
    ActUpdate: TAction;
    ActUpgrade: TAction;
    MenuItem3: TMenuItem;
    MenuItem7: TMenuItem;
    TrayUpdate: TImageList;
    TrayRunning: TImageList;
    MenuItem1: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    MenuItem6: TMenuItem;
    PopupMenu1: TPopupMenu;
    TrayIcon1: TTrayIcon;
    UniqueInstance1:TUniqueInstance;
    procedure ActConfigureExecute(Sender: TObject);
    procedure ActLaunchGuiExecute(Sender: TObject);
    procedure ActLaunchGuiUpdate(Sender: TObject);
    procedure ActQuitExecute(Sender: TObject);
    procedure ActShowStatusExecute(Sender: TObject);
    procedure ActUpdateExecute(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleDestroy(Sender: TObject);
    procedure TrayIcon1DblClick(Sender: TObject);
    procedure UniqueInstance1OtherInstance(Sender: TObject;
      ParamCount: Integer; Parameters: array of String);
  private
    procedure SetTrayIcon(idx: integer);
    function WinapticFileName: String;
    { private declarations }
  public
    { public declarations }
    check_thread:TThread;
    checkinterval:Integer;
  end;

var
  DMWaptTray: TDMWaptTray;

implementation
uses LCLIntf,Forms,windows,superobject,graphics,tiscommon,waptcommon,tisinifiles;

{$R *.lfm}
type

  { TCheckThread }

  TCheckThread = Class(TThread)
    public
      new_updates,new_upgrades,runstatus : String;
      new_hint:String;
      new_ballon:String;
      animate_upgrade,
      animate_running:Boolean;
      icon_idx:integer;
      previousupgrades:String;
      DMTray:TDMWaptTray;
      running : ISuperObject;
      checkinterval:integer;
      procedure Execute; override;
      procedure SetTrayStatus;
      procedure ResetPreviousUpgrades;
  end;

{ TCheckThread }

procedure TCheckThread.Execute;
var
  sob,rs:ISuperObject;
begin
  repeat
    try
      new_hint :='';
      new_ballon:='';
      animate_running := False;
      animate_upgrade := False;
      icon_idx:=-1;

      //test running tasks first
      runstatus := httpGetString('http://localhost:8088/runstatus');
      rs := SO(runstatus);
      if rs.S['value']<>'' then
      begin
        animate_running :=True;
        new_hint:=rs.S['value'];
      end
      else
      begin
        new_updates := httpGetString('http://localhost:8088/checkupgrades');
        sob := SO(new_updates);
        running := sob['running_tasks'];
        new_upgrades := sob.S['upgrades'];

        if (running<>Nil) and (running.AsArray.Length>0) then
        begin
          animate_running :=True;
          new_hint:='Installation en cours : '+running.AsString;
        end
        else
        if new_upgrades<>'[]' then
        begin
          animate_upgrade :=True;
          new_hint:='Mises à jour disponibles pour : '+new_upgrades;
        end
        else
        begin
          new_hint:='Système à jour';
          icon_idx:=0;
        end;

        if new_upgrades<>previousupgrades then
        begin
          if (new_upgrades<>'[]') and (Length(new_upgrades)>length(previousupgrades)) then
            new_ballon:='Nouvelles mises à jour disponibles'
          else
            if (running<>Nil) and (running.AsArray.Length>0) then
              new_ballon:='Installation en cours : '+running.AsString
            else if (new_upgrades='[]') then
              new_ballon:='Système à jour';
          previousupgrades:=new_upgrades;
        end;
      end;
      Synchronize(@SetTrayStatus);
    except
      on e:Exception do
      begin
        new_hint:='Impossible d''obtenir le status de mise à jour'+#13#10+e.Message;
        icon_idx := 1;
        Synchronize(@SetTrayStatus);
      end;
    end;
    if not Terminated then
      Sleep(CheckInterval);
  until Terminated;
end;

procedure TCheckThread.SetTrayStatus;
begin
    if animate_running then
    begin
      DMTray.TrayIcon1.Icons := DMTray.TrayRunning;
      DMTray.TrayIcon1.Animate:=True;
    end
    else
    if animate_upgrade then
    begin
      DMTray.TrayIcon1.Icons := DMTray.TrayUpdate;
      DMTray.TrayIcon1.Animate:=True;
    end
    else
    if icon_idx>=0 then
      DMTray.SetTrayIcon(icon_idx);

    if new_hint<>'' then
      DMTray.TrayIcon1.Hint:=new_hint;

    if new_ballon<>'' then
    begin
      DMTray.TrayIcon1.BalloonHint:=new_ballon;
      DMTray.TrayIcon1.ShowBalloonHint;
    end;
end;

procedure TCheckThread.ResetPreviousUpgrades;
begin
  previousupgrades:='';
end;

{ TVisWAPTTray }

procedure TDMWaptTray.ActShowStatusExecute(Sender: TObject);
begin
  OpenURL('http://localhost:8088/status');
end;

procedure TDMWaptTray.ActUpdateExecute(Sender: TObject);
begin
  TCheckThread(check_thread).Synchronize(@TCheckThread(check_thread).ResetPreviousUpgrades);
  OpenURL('http://localhost:8088/update');

  TrayIcon1.BalloonHint:='Mise à jour des logiciels disponibles lancée';
  TrayIcon1.ShowBalloonHint;
end;

procedure TDMWaptTray.ActUpgradeExecute(Sender: TObject);
var
  res : String;
begin
  TCheckThread(check_thread).Synchronize(@TCheckThread(check_thread).ResetPreviousUpgrades);
  res := httpGetString( 'http://localhost:8088/upgrade');
  if pos('ERROR',uppercase(res))<=0 then
    TrayIcon1.BalloonHint:='Mise à jour des logiciels lancée en tâche de fond...'
  else
    TrayIcon1.BalloonHint:='Erreur au lancement de la mise à jour des logiciels...';
  TrayIcon1.ShowBalloonHint;
end;

procedure TDMWaptTray.DataModuleCreate(Sender: TObject);
begin
  checkinterval:=IniReadInteger(WaptIniFilename,'Global','tray_check_interval')*1000;
  if checkinterval=0 then
    checkinterval:=10000;

  check_thread :=  TCheckThread.Create(True);
  TCheckThread(check_thread).DMTray := Self;
  TCheckThread(check_thread).checkinterval:=checkinterval;
  check_thread.Resume;
end;

procedure TDMWaptTray.DataModuleDestroy(Sender: TObject);
begin
  TerminateThread(check_thread.Handle,0);
  FreeAndNil(check_thread);
end;

procedure TDMWaptTray.ActConfigureExecute(Sender: TObject);
begin
  OpenDocument(WaptIniFilename);
end;

procedure TDMWaptTray.ActLaunchGuiExecute(Sender: TObject);
var
  cmd:String;
begin
  cmd := WinapticFileName;
  ShellExecute(0,Pchar('open'),PChar(cmd),Nil,Nil,0);
end;

function TDMWaptTray.WinapticFileName:String;
begin
  result:=AppendPathDelim(ExtractFileDir(ParamStr(0)))+'winaptic.exe';
end;

procedure TDMWaptTray.ActLaunchGuiUpdate(Sender: TObject);
begin
  ActLaunchGui.Enabled:=FileExists(WinapticFileName);
end;

procedure TDMWaptTray.ActQuitExecute(Sender: TObject);
begin
  check_thread.Terminate;
  Application.Terminate;
end;

procedure TDMWaptTray.SetTrayIcon(idx:integer);
var
  lBitmap: TBitmap;
begin
  TrayIcon1.Animate:=False;
  lBitmap := TBitmap.Create;
  try
    TrayUpdate.GetBitmap(idx, lBitmap);
    TrayIcon1.Icon.Assign(lBitmap);
    TrayIcon1.InternalUpdate();
  finally
    lBitmap.Free;
  end;
end;


procedure TDMWaptTray.TrayIcon1DblClick(Sender: TObject);
begin
  TCheckThread(check_thread).Synchronize(@TCheckThread(check_thread).ResetPreviousUpgrades);
end;

procedure TDMWaptTray.UniqueInstance1OtherInstance(Sender: TObject;
  ParamCount: Integer; Parameters: array of String);
begin

end;

end.

