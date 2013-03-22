unit uwapttray;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, BufDataset, FileUtil, Forms, Controls, Graphics, Dialogs,
  ExtCtrls, Menus, ActnList, StdCtrls, ValEdit;

type

  { TVisWAPTTray }

  TVisWAPTTray = class(TForm)
    ActForceRegisterComputer: TAction;
    ActShowStatus: TAction;
    ActQuit: TAction;
    ActShowMain: TAction;
    ActUpdate: TAction;
    ActUpgrade: TAction;
    ActionList1: TActionList;
    MenuItem6: TMenuItem;
    MenuItem1: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    PopupMenu1: TPopupMenu;
    Timer1: TTimer;
    TrayIcon1: TTrayIcon;
    procedure ActQuitExecute(Sender: TObject);
    procedure ActShowMainExecute(Sender: TObject);
    procedure ActShowStatusExecute(Sender: TObject);
    procedure ActUpdateExecute(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormShow(Sender: TObject);
    procedure MenuItem2Click(Sender: TObject);
    procedure MenuItem3Click(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
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

uses waptcommon, superobject,tiscommon,Process,LCLIntf;

{$R *.lfm}

{ TVisWAPTTray }

procedure TVisWAPTTray.TrayIcon1Click(Sender: TObject);
begin

end;

procedure TVisWAPTTray.ActShowMainExecute(Sender: TObject);
begin
  Show;
end;

procedure TVisWAPTTray.ActShowStatusExecute(Sender: TObject);
begin
  OpenURL('http://localhost:8088/status');
end;

procedure TVisWAPTTray.ActUpdateExecute(Sender: TObject);
begin
  OpenURL('http://localhost:8088/update');
end;

procedure TVisWAPTTray.ActUpgradeExecute(Sender: TObject);
begin
  OpenURL('http://localhost:8088/upgrade');
end;

procedure TVisWAPTTray.ActQuitExecute(Sender: TObject);
begin
  Application.Terminate;
end;

procedure TVisWAPTTray.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  CloseAction:=caHide;
end;

procedure TVisWAPTTray.FormShow(Sender: TObject);
var
  s:SOString;
begin
  {s := UTF8Decode(httpGetString  ('http://localhost:'+intToStr(waptservice_port)+'/sysinfo'));
  sysinfo.Lines.Text:= UTF8Encode(TSuperObject.ParseString(pwidechar(s),False).AsJSon(True));}
end;

procedure TVisWAPTTray.MenuItem2Click(Sender: TObject);
begin

end;

procedure TVisWAPTTray.MenuItem3Click(Sender: TObject);
begin

end;

procedure TVisWAPTTray.Timer1Timer(Sender: TObject);
begin
  //update_pending := httpGetString('http://localhost:8088/);
end;

procedure TVisWAPTTray.TrayIcon1DblClick(Sender: TObject);
begin
  ActShowMain.Execute;
end;

end.

