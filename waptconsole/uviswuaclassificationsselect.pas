unit uVisWUAClassificationsSelect;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ButtonPanel,
  StdCtrls, sogrid;

type

  { TVisWUAClassificationsSelect }

  TVisWUAClassificationsSelect = class(TForm)
    ButtonPanel1: TButtonPanel;
    GridWinClassifications: TSOGrid;
    Label1: TLabel;
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormShow(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisWUAClassificationsSelect: TVisWUAClassificationsSelect;

implementation
uses waptcommon;
{$R *.lfm}

{ TVisWUAClassificationsSelect }

procedure TVisWUAClassificationsSelect.FormCloseQuery(Sender: TObject;
  var CanClose: boolean);
begin
  CanClose := (ModalResult = mrCancel) or ((GridWinClassifications.Focused or ButtonPanel1.OKButton.Focused) and (GridWinClassifications.SelectedCount>0));
end;

procedure TVisWUAClassificationsSelect.FormShow(Sender: TObject);
begin
    GridWinClassifications.Data := WAPTServerJsonGet('api/v2/windows_updates_classifications',[])['result'];

end;

end.

