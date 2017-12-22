unit uvislogin;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons, ButtonPanel, LCLType, EditBtn, ActnList;

type

  { TVisLogin }

  TVisLogin = class(TForm)
    ActSelectConf: TAction;
    ActionList1: TActionList;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    BitBtn3: TBitBtn;
    CBConfiguration: TComboBox;
    edPassword: TEdit;
    EdUser: TEdit;
    edWaptServerName: TEdit;
    Image1: TImage;
    LabVersion: TLabel;
    labServer: TLabel;
    laPassword: TLabel;
    labUser: TLabel;
    laConfiguration: TLabel;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
    procedure ActSelectConfExecute(Sender: TObject);
    procedure BitBtn1Click(Sender: TObject);
    procedure CBConfigurationDropDown(Sender: TObject);
    procedure CBConfigurationKeyPress(Sender: TObject; var Key: char);
    procedure CBConfigurationSelect(Sender: TObject);
    procedure edPasswordKeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
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
uses LCLIntf,  uwaptconsole,waptcommon, DefaultTranslator,UScaleDPI,tiscommon,tisinifiles;
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

procedure TVisLogin.FormCloseQuery(Sender: TObject; var CanClose: boolean);
begin
  if (ModalResult=mrOK) then
    CanClose := (edWaptServerName.Text<>'') and (EdUser.text<>'') and (edPassword.Text<>'')
  else
    CanClose := True;
  if not CanClose then
  begin
    if (edWaptServerName.Text='') and CBConfiguration.Visible then
      CBConfiguration.SetFocus
    else if (EdUser.text='') then
      EdUser.SetFocus
    else if (edPassword.Text='') then
      edPassword.SetFocus;
  end;
end;

procedure TVisLogin.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  LabVersion.Caption := ApplicationName+' '+wapt_edition+' Edition '+GetApplicationVersion;
end;

procedure TVisLogin.FormShow(Sender: TObject);
begin
  {$ifdef ENTERPRISE }
  CBConfiguration.Text := AppIniFilename;
  {$endif}

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

procedure TVisLogin.ActSelectConfExecute(Sender: TObject);
begin
  {$ifdef ENTERPRISE }
  ActSelectConf.Checked:=not ActSelectConf.Checked;
  laConfiguration.Visible := ActSelectConf.Checked;
  CBConfiguration.Visible := ActSelectConf.Checked;
  if ActSelectConf.Checked then
    CBConfiguration.SetFocus;
  {$endif}
end;

procedure TVisLogin.CBConfigurationDropDown(Sender: TObject);
var
  ConfigList:TStringList;
  i:integer;
  conf:String;
begin
  {$ifdef ENTERPRISE }
  try
    CBConfiguration.Items.Clear;
    ConfigList := FindAllFiles(GetAppConfigDir(False),'*.ini',False);
    for conf in ConfigList do
    begin
      CBConfiguration.Items.Add(ExtractFileNameOnly(Conf));
    end;
  finally
    ConfigList.Free;
  end;
  {$endif}
end;

procedure TVisLogin.CBConfigurationKeyPress(Sender: TObject; var Key: char);
begin
  {$ifdef ENTERPRISE }
  if key = #13 then
  begin
    if (edWaptServerName.Text <>'') and  (EdUser.Text <>'') then
      edPassword.SetFocus;
    Key := #0;
  end;
  {$endif}
end;

procedure TVisLogin.CBConfigurationSelect(Sender: TObject);
begin
  {$ifdef ENTERPRISE }
  if ExtractFileDir(CBConfiguration.Text) = '' then
    FAppIniFilename := AppendPathDelim(GetAppConfigDir(False))+CBConfiguration.Text+'.ini'
  else
    FAppIniFilename := CBConfiguration.Text;
  edWaptServerName.Text:=IniReadString(FAppIniFilename,'global','wapt_server');
  {$endif}
end;



end.

