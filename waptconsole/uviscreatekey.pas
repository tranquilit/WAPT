unit uVisCreateKey;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  StdCtrls, Buttons, EditBtn;

type

  { TVisCreateKey }

  TVisCreateKey = class(TForm)
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    DirectoryCert: TDirectoryEdit;
    edCountry: TEdit;
    edCommonName: TEdit;
    edEmail: TEdit;
    edUnit: TEdit;
    edOrganization: TEdit;
    edLocality: TEdit;
    EdOrgName: TEdit;
    Label1: TLabel;
    Label10: TLabel;
    Label12: TLabel;
    Label13: TLabel;
    Label14: TLabel;
    Label15: TLabel;
    Label16: TLabel;
    Label9: TLabel;
    Panel1: TPanel;
    Panel2: TPanel;
    Shape1: TShape;
    StaticText1: TStaticText;
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisCreateKey: TVisCreateKey;

implementation
{$R *.lfm}

{ TVisCreateKey }

procedure TVisCreateKey.FormCloseQuery(Sender: TObject; var CanClose: boolean);
var
  pemfn:String;
begin
  pemfn:=DirectoryCert.Directory+'\'+EdOrgName.Text+'.pem';
  if (ModalResult=mrOk) and (EdOrgName.Text = '') then
     begin
          showMessage('Veuillez rentrer un nom de clé');
          CanClose:=False;
      end
  else
      if (ModalResult=mrOk) and FileExists(pemfn) then
      begin
           ShowMessage(format('La clé %s existe déjà, choisir un autre nom de clé',[pemfn]));
           CanClose:=False;
      end
      else
          CanClose:=True;
end;

end.

