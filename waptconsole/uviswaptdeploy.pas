unit uviswaptdeploy;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons;

type

  { Tviswaptdeploy }

  Tviswaptdeploy = class(TForm)
    BitBtn2: TBitBtn;
    Button5: TButton;
    EdDomaine: TLabeledEdit;
    EdDomainUser: TLabeledEdit;
    EdDomainPassword: TLabeledEdit;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Memo1: TMemo;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel4: TPanel;
    procedure FormCreate(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  viswaptdeploy: Tviswaptdeploy;

implementation
uses tiscommon;
{$R *.lfm}

{ Tviswaptdeploy }

procedure Tviswaptdeploy.FormCreate(Sender: TObject);
begin
  EdDomaine.Text := GetDomainName;
end;

end.

