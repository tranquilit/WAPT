unit uVisSettings;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  Buttons, ExtCtrls, Menus, ActnList, ComCtrls;

type

  { TVisSettings }

  TVisSettings = class(TForm)
    ButCancel: TBitBtn;
    ButOk: TBitBtn;
    ComboBoxLang: TComboBox;
    Language: TLabel;
    PanelSettings: TPanel;
    PanelBtn: TPanel;
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private

  public

  end;

var
  VisSettings: TVisSettings;

implementation

uses LCLTranslator;

{$R *.lfm}

{ TVisSettings }

procedure TVisSettings.FormCreate(Sender: TObject);
begin
  if (GetDefaultLang='fr') then
    ComboBoxLang.ItemIndex:=ComboBoxLang.Items.IndexOf('Français')
  else
    ComboBoxLang.ItemIndex:=ComboBoxLang.Items.IndexOf('English');
end;

procedure TVisSettings.FormShow(Sender: TObject);
begin
  MakeFullyVisible();
  ComboBoxLang.SetFocus;
end;

end.

