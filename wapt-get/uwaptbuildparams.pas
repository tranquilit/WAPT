unit uWaptBuildParams;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons,DefaultTranslator, ActnList;

type

  { TBisWaptBuildParams }

  { TVisWaptBuildParams }

  TVisWaptBuildParams = class(TForm)
    ActSelectConf: TAction;
    ActOK: TAction;
    ActionList1: TActionList;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    CBConfiguration: TComboBox;
    edPassword: TEdit;
    edKeyPassword: TEdit;
    EdUser: TEdit;
    edWaptServerName: TEdit;
    LabKeyPath: TLabel;
    labServer: TLabel;
    labUser: TLabel;
    LabConfiguration: TLabel;
    EdKeyPath: TLabel;
    labKeyPassword: TLabel;
    LabPassword: TLabel;
    PanBottom: TPanel;
    Panel1: TPanel;
    Panel3: TPanel;
    procedure ActOKExecute(Sender: TObject);
    procedure ActSelectConfExecute(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisWaptBuildParams: TVisWaptBuildParams;

implementation

uses uSCaleDPI,LCLIntf,tisinifiles;

{$R *.lfm}

{ TVisWaptBuildParams }

procedure TVisWaptBuildParams.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
end;

procedure TVisWaptBuildParams.ActOKExecute(Sender: TObject);
begin
  If CBConfiguration.Visible and (CBConfiguration.text = '') then
    CBConfiguration.SetFocus
  else if EdUser.Visible and (EdUser.text = '') then
    EdUser.SetFocus
  else if edPassword.Visible and (edPassword.text = '') then
    edPassword.SetFocus
  else if edKeyPassword.Visible and (edKeyPassword.text = '') then
    edKeyPassword.SetFocus
  else
    ModalResult:=mrOK;
end;

procedure TVisWaptBuildParams.ActSelectConfExecute(Sender: TObject);
begin
  ActSelectConf.Checked:=not ActSelectConf.Checked;
  LabConfiguration.Visible := ActSelectConf.Checked;
  CBConfiguration.Visible := ActSelectConf.Checked;
  if ActSelectConf.Checked then
    CBConfiguration.SetFocus;

end;

procedure TVisWaptBuildParams.FormShow(Sender: TObject);
begin
  Application.BringToFront;
  BringToFront;
  SetFocus;
end;

end.

