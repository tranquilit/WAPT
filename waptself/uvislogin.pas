unit uVisLogin;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  Buttons, ExtCtrls;

type

  { TVisLogin }

  TVisLogin = class(TForm)
    ButOk: TBitBtn;
    ButCancel: TBitBtn;
    EdUsername: TEdit;
    EdPassword: TEdit;
    LogoLogin: TImage;
    ImageWarning: TImage;
    ImgWarning: TImage;
    Panel1: TPanel;
    WarningPanel: TPanel;
    PanelLogin: TPanel;
    StaticText1: TStaticText;
    StaticText2: TStaticText;
    WarningText: TStaticText;
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure LogoLoginClick(Sender: TObject);
    procedure LogoLoginMouseEnter(Sender: TObject);
    procedure LogoLoginMouseLeave(Sender: TObject);
  private

  public

  end;

var
  VisLogin: TVisLogin;

implementation

uses waptcommon, LCLIntf, uVisWaptSelf;

{$R *.lfm}

{ TVisLogin }

procedure TVisLogin.FormShow(Sender: TObject);
begin
  MakeFullyVisible();
  if EdUsername.Text<>'' then
    EdPassword.SetFocus
  else
    EdUsername.SetFocus;
end;

procedure TVisLogin.LogoLoginClick(Sender: TObject);
begin
  {$ifndef ENTERPRISE }
    OpenDocument('https://www.tranquil.it/solutions/wapt-deploiement-d-applications/');
  {$endif}
end;

procedure TVisLogin.LogoLoginMouseEnter(Sender: TObject);
begin
  Screen.Cursor:=crHandPoint;
end;

procedure TVisLogin.LogoLoginMouseLeave(Sender: TObject);
begin
  Screen.Cursor:=crDefault;
end;

procedure TVisLogin.FormCreate(Sender: TObject);
begin
  {$ifdef ENTERPRISE }
  if FileExists(WaptBaseDir+'\templates\waptself-logo.png') then
    LogoLogin.Picture.LoadFromFile(WaptBaseDir+'\templates\waptself-logo.png')
  else
    LogoLogin.Picture.LoadFromResourceName(HINSTANCE,'SELF-SERVICE-ENTERPRISE-200PX');
  {$endif}
  if Screen.PixelsPerInch <> 96 then
  begin
     LogoLogin.AutoSize:=false;
     LogoLogin.Height:=VisWaptSelf.GoodSizeForScreen(LogoLogin.Height);
     LogoLogin.Width:=VisWaptSelf.GoodSizeForScreen(LogoLogin.Width);
     LogoLogin.AntialiasingMode:=amOn;
     ImageWarning.AutoSize:=false;
     ImageWarning.AntialiasingMode:=amOn;
  end;
end;

end.

