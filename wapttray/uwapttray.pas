unit uwapttray;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  Menus, ActnList;

type

  { TVisWAPTTray }

  TVisWAPTTray = class(TForm)
    ActForceRegisterComputer: TAction;
    ActQuit: TAction;
    ActShowMain: TAction;
    ActUpdate: TAction;
    ActUpgrade: TAction;
    ActionList1: TActionList;
    MenuItem1: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem3: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    PopupMenu1: TPopupMenu;
    TrayIcon1: TTrayIcon;
    procedure ActQuitExecute(Sender: TObject);
    procedure ActShowMainExecute(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure TrayIcon1Click(Sender: TObject);
    procedure TrayIcon1DblClick(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisWAPTTray: TVisWAPTTray;

implementation

{$R *.lfm}

{ TVisWAPTTray }

procedure TVisWAPTTray.TrayIcon1Click(Sender: TObject);
begin

end;

procedure TVisWAPTTray.ActShowMainExecute(Sender: TObject);
begin
  Show;
end;

procedure TVisWAPTTray.ActQuitExecute(Sender: TObject);
begin
  Close;
end;

procedure TVisWAPTTray.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  CloseAction:=caHide;
end;

procedure TVisWAPTTray.TrayIcon1DblClick(Sender: TObject);
begin
  ActShowMain.Execute;
end;

end.

