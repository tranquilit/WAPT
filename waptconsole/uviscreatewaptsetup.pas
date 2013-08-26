unit uVisCreateWaptSetup;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  EditBtn, ExtCtrls, Buttons, ActnList;

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
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisCreateWaptSetup: TVisCreateWaptSetup;

implementation

{$R *.lfm}

{ TVisCreateWaptSetup }
procedure TVisCreateWaptSetup.FormCloseQuery(Sender: TObject; var CanClose: boolean);
begin
  CanClose:= True;
  if (ModalResult=mrOk) then
  begin
    if fnPublicCert.FileName='' then
    begin
      showMessage('Veuillez rentrer le chemin vers la clé publique');
      CanClose:=False;
    end;
    if (edRepoUrl.Text = '') then
    begin
      ShowMessage('Veuillez rentrer l''adresse du dépot Wapt ');
      CanClose:=False;
    end;
    if (edWaptServerUrl.Text = '') then
    begin
      ShowMessage('Veuillez rentrer l''adresse du serveur Wapt ');
      CanClose:=False;
    end;
    if DirectoryExists(fnWaptDirectory.Directory) then
    begin
      ShowMessage('Le répertoire pour sauvegarder waptsetup n''est pas valide: '+fnWaptDirectory.Directory);
      CanClose:=False;
    end
  end;
end;

end.

