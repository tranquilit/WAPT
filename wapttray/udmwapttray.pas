unit uDMWAPTTray;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, ExtCtrls, Menus, ActnList, Controls;

type

  { TDMWaptTray }
  TDMWaptTray = class(TDataModule)
    ActForceRegisterComputer: TAction;
    ActConfigure: TAction;
    ActionList1: TActionList;
    ActQuit: TAction;
    ActShowMain: TAction;
    ActShowStatus: TAction;
    ActUpdate: TAction;
    ActUpgrade: TAction;
    ImageList1: TImageList;
    MenuItem1: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    MenuItem6: TMenuItem;
    PopupMenu1: TPopupMenu;
    Timer1: TTimer;
    TrayIcon1: TTrayIcon;
    procedure ActConfigureExecute(Sender: TObject);
    procedure ActForceRegisterComputerExecute(Sender: TObject);
    procedure ActQuitExecute(Sender: TObject);
    procedure ActShowMainExecute(Sender: TObject);
    procedure ActShowStatusExecute(Sender: TObject);
    procedure ActUpdateExecute(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleDestroy(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
    procedure TrayIcon1Click(Sender: TObject);
    procedure TrayIcon1DblClick(Sender: TObject);
  private
    procedure SetTrayIcon(idx: integer);
    { private declarations }
  public
    { public declarations }
    check_thread:TThread;
  end;

var
  DMWaptTray: TDMWaptTray;

implementation
uses LCLIntf,Forms,windows,superobject,graphics,tiscommon,waptcommon;

{$R *.lfm}
type

  { TCheckThread }

  TCheckThread = Class(TThread)
    public
      new_updates,new_upgrades : String;
      new_hint:String;
      new_ballon:String;
      animate:Boolean;
      icon_idx:integer;
      previousupgrades:String;
      DMTray:TDMWaptTray;
      procedure Execute; override;
      procedure SetTrayStatus;
  end;

{ TCheckThread }

procedure TCheckThread.Execute;
var
  sob:ISuperObject;
begin
  while not Terminated do
  begin
    try
      new_hint :='';
      new_ballon:='';
      animate := False;
      icon_idx:=-1;
      new_updates := httpGetString('http://localhost:8088/checkupgrades');
      sob := SO(new_updates);
      new_upgrades := sob.S['upgrades'];
      if new_upgrades<>'[]' then
      begin
        animate:=True;
        new_hint:='Mises à jour disponibles pour : '+new_upgrades;
      end
      else
      begin
        new_hint:='Système à jour';
        icon_idx:=0;
      end;

      if new_upgrades<>previousupgrades then
      begin
        if new_upgrades<>'[]' then
          new_ballon:='Nouvelles mises à jour disponibles'
        else
          new_ballon:='Système à jour';

        previousupgrades:=new_upgrades;
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
    Sleep(10000);
  end;
end;

procedure TCheckThread.SetTrayStatus;
begin
    if animate then
    begin
      DMTray.TrayIcon1.Icons := DMTray.ImageList1;
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

{ TVisWAPTTray }

procedure TDMWaptTray.ActShowMainExecute(Sender: TObject);
begin
end;

procedure TDMWaptTray.ActShowStatusExecute(Sender: TObject);
begin
  OpenURL('http://localhost:8088/status');
end;

procedure TDMWaptTray.ActUpdateExecute(Sender: TObject);
begin
  OpenURL('http://localhost:8088/update');
end;

procedure TDMWaptTray.ActUpgradeExecute(Sender: TObject);
begin
  OpenURL('http://localhost:8088/upgrade');
end;

procedure TDMWaptTray.DataModuleCreate(Sender: TObject);
begin
  check_thread :=  TCheckThread.Create(True);
  TCheckThread(check_thread).DMTray := Self;
  check_thread.Resume;
end;

procedure TDMWaptTray.DataModuleDestroy(Sender: TObject);
begin
  check_thread.Terminate;
  FreeAndNil(check_thread);
end;

procedure TDMWaptTray.ActForceRegisterComputerExecute(Sender: TObject);
begin

end;

procedure TDMWaptTray.ActConfigureExecute(Sender: TObject);
begin
  OpenDocument(WaptIniFilename);
end;

procedure TDMWaptTray.ActQuitExecute(Sender: TObject);
begin
  Application.Terminate;
end;

procedure TDMWaptTray.SetTrayIcon(idx:integer);
var
  lBitmap: TBitmap;
begin
  TrayIcon1.Animate:=False;
  lBitmap := TBitmap.Create;
  try
    ImageList1.GetBitmap(idx, lBitmap);
    TrayIcon1.Icon.Assign(lBitmap);
    TrayIcon1.InternalUpdate();
  finally
    lBitmap.Free;
  end;
end;


procedure TDMWaptTray.Timer1Timer(Sender: TObject);
begin
end;

procedure TDMWaptTray.TrayIcon1Click(Sender: TObject);
begin

end;

procedure TDMWaptTray.TrayIcon1DblClick(Sender: TObject);
begin
  Timer1Timer(Sender);
end;

end.

