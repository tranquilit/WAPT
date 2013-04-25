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
    procedure TrayIcon1DblClick(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  DMWaptTray: TDMWaptTray;

implementation
uses LCLIntf,Forms,windows,waptcommon, superobject,tiscommon;

{$R *.lfm}

{ TVisWAPTTray }

procedure TDMWaptTray.ActShowMainExecute(Sender: TObject);
begin
  TrayIcon1.Icons := ImageList1;
  //TrayIcon1.Animate:=True;
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
begin
  //update_pending := httpGetString('http://localhost:8088/checkupdates');
end;

procedure TDMWaptTray.TrayIcon1DblClick(Sender: TObject);
begin
  ActShowMain.Execute;
end;

end.

