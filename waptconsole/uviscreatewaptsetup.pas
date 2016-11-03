unit uVisCreateWaptSetup;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  EditBtn, ExtCtrls, Buttons, ActnList, DefaultTranslator, uWaptConsoleRes;

type

  { TVisCreateWaptSetup }

  TVisCreateWaptSetup = class(TForm)
    ActionList1: TActionList;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    edWaptServerUrl: TEdit;
    fnWaptDirectory: TDirectoryEdit;
    edRepoUrl: TEdit;
    edOrgName: TEdit;
    fnPublicCert: TFileNameEdit;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Panel1: TPanel;
    procedure fnPublicCertEditingDone(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisCreateWaptSetup: TVisCreateWaptSetup;

implementation

{$R *.lfm}

uses
  uWaptRes,UScaleDPI, dmwaptpython;

{ TVisCreateWaptSetup }
procedure TVisCreateWaptSetup.FormCloseQuery(Sender: TObject; var CanClose: boolean);
begin
  CanClose:= True;
  if (ModalResult=mrOk) then
  begin
    if fnPublicCert.FileName='' then
    begin
      showMessage(rsInputPubKeyPath);
      CanClose:=False;
    end;
    if not DirectoryExists(fnWaptDirectory.Caption) then
    begin
      ShowMessageFmt(rsInvalidWaptSetupDir, [fnWaptDirectory.Directory]);
      CanClose:=False;
    end
  end;
end;

procedure TVisCreateWaptSetup.fnPublicCertEditingDone(Sender: TObject);
begin
  if FileExists(fnPublicCert.FileName) then
    edOrgName.text := dmwaptpython.DMPython.PythonEng.EvalStringAsStr(Format('common.SSLCertificate(r"""%s""").cn',[fnPublicCert.FileName]));

end;

procedure TVisCreateWaptSetup.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
end;

procedure TVisCreateWaptSetup.FormShow(Sender: TObject);
begin
  if edOrgName.Text='' then
    if FileExists(fnPublicCert.FileName) then
      edOrgName.text := dmwaptpython.DMPython.PythonEng.EvalStringAsStr(Format('common.SSLCertificate(r"""%s""").cn',[fnPublicCert.FileName]));
end;

end.

