unit uvislogin;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons, ButtonPanel, LCLType, EditBtn;

type

  { TVisLogin }

  TVisLogin = class(TForm)
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    BitBtn3: TBitBtn;
    edPassword: TEdit;
    EdUser: TEdit;
    edWaptServerName: TEdit;
    Image1: TImage;
    LabVersion: TLabel;
    labServer: TLabel;
    laPassword: TLabel;
    labUser: TLabel;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
    procedure BitBtn1Click(Sender: TObject);
    procedure edPasswordKeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure Image1Click(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisLogin: TVisLogin;

implementation
uses LCLIntf,  uwaptconsole,waptcommon, DefaultTranslator,UScaleDPI,tiscommon;
{$R *.lfm}

{ TVisLogin }

procedure TVisLogin.edPasswordKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
    if Key = VK_RETURN then
  begin
    edPassword.SelectAll;
  end;
end;

procedure TVisLogin.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  LabVersion.Caption := ApplicationName+' '+GetApplicationVersion;
end;

procedure TVisLogin.FormShow(Sender: TObject);
begin
  if edUser.Text<>'' then
    edPassword.SetFocus;
end;

procedure TVisLogin.Image1Click(Sender: TObject);
begin
  OpenDocument('https://www.tranquil.it');
end;

procedure TVisLogin.BitBtn1Click(Sender: TObject);
begin
  if VisWaptGUI.EditIniFile then
  begin
    VisWaptGUI.ActReloadConfig.Execute;
    edWaptServerName.Text:=waptcommon.GetWaptServerURL;
  end;
end;



end.

