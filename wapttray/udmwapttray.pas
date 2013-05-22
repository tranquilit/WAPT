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
    procedure Timer1Timer(Sender: TObject);
    procedure TrayIcon1Click(Sender: TObject);
    procedure TrayIcon1DblClick(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
    previousupgrades:String;
  end;

var
  DMWaptTray: TDMWaptTray;

implementation
uses LCLIntf,Forms,windows,waptcommon, superobject,tiscommon;

{$R *.lfm}

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

procedure TDMWaptTray.Timer1Timer(Sender: TObject);
var
  sob:ISuperObject;
  new_updates,new_upgrades : String;
begin
  try
    new_updates := httpGetString('http://localhost:8088/checkupgrades');
    sob := SO(new_updates);
    new_upgrades := SOb.S['upgrades'];
    if new_upgrades<>'[]' then
    begin
      TrayIcon1.Icons := ImageList1;
      TrayIcon1.Animate:=True;
      TrayIcon1.Hint:='Mises à jour disponibles pour : '+new_upgrades;
    end
    else
    begin
      TrayIcon1.Hint:='Système à jour';
      TrayIcon1.Animate:=False;
    end;

    if new_upgrades<>previousupgrades then
    begin
      if new_upgrades<>'[]' then
        TrayIcon1.BalloonHint:='Nouvelles mises à jour disponibles'
      else
        TrayIcon1.BalloonHint:='Système à jour';

      TrayIcon1.ShowBalloonHint;
      previousupgrades:=new_upgrades;
    end;
  except
    TrayIcon1.Hint:='Impossible d''obtenir les status de mise à jour';
    //TrayIcon1.Hint:='Impossible d''obtenir les status de mise à jour';
    //TrayIcon1.ShowBalloonHint;
  end;
end;

procedure TDMWaptTray.TrayIcon1Click(Sender: TObject);
begin

end;

procedure TDMWaptTray.TrayIcon1DblClick(Sender: TObject);
begin
  Timer1Timer(Sender);
end;

end.

