unit uVisDisplayPreferences;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  Buttons,DefaultTranslator, StdCtrls;

type

  { TVisDisplayPreferences }

  TVisDisplayPreferences = class(TForm)
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    cbDebugWindow: TCheckBox;
    cbEnableExternalTools: TCheckBox;
    cbEnableManagementFeatures: TCheckBox;
    cbLanguage: TComboBox;
    EdHostsLimit: TEdit;
    Label1: TLabel;
    Label10: TLabel;
    Label11: TLabel;
    Label3: TLabel;
    Label7: TLabel;
    Panel1: TPanel;
    Panel2: TPanel;
    procedure FormCreate(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisDisplayPreferences: TVisDisplayPreferences;

implementation
uses uSCaleDPI;
{$R *.lfm}

{ TVisDisplayPreferences }

procedure TVisDisplayPreferences.FormCreate(Sender: TObject);
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed

end;

end.

