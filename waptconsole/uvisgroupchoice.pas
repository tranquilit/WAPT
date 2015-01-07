unit uvisgroupchoice;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, ButtonPanel, ActnList, sogrid, superobject, dmwaptpython, LCLType, DefaultTranslator;

type

  { TvisGroupChoice }

  TvisGroupChoice = class(TForm)
    ActSearch: TAction;
    ActionList1: TActionList;
    butSearchGroups: TButton;
    ButtonPanel1: TButtonPanel;
    cbBase: TCheckBox;
    cbGroup: TCheckBox;
    cbrestricted: TCheckBox;
    EdSearch: TEdit;
    groupGrid: TSOGrid;
    Label2: TLabel;
    Panel1: TPanel;
    procedure ActSearchExecute(Sender: TObject);
    procedure cbBaseClick(Sender: TObject);
    procedure EdSearchKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState
      );
    procedure FormShow(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  visGroupChoice: TvisGroupChoice;

implementation

{$R *.lfm}

{ TvisGroupChoice }

procedure TvisGroupChoice.ActSearchExecute(Sender: TObject);
var
  expr, res, sections: UTF8String;
  groups : ISuperObject;
begin
  sections := '';
  if cbGroup.Checked then
    sections := sections+',group';
  if cbBase.Checked then
    sections := sections+',base';
  if cbrestricted.Checked then
    sections := sections+',restricted';
  sections := copy(sections,2,255);
  expr := format('mywapt.search(r"%s".decode(''utf8'').split(),section_filter="%s")', [EdSearch.Text,sections]);
  groups := DMPython.RunJSON(expr);
  groupGrid.Data := groups;
  //groupGrid.Header.AutoFitColumns(False);
end;

procedure TvisGroupChoice.cbBaseClick(Sender: TObject);
begin
  ActSearch.Execute;
end;

procedure TvisGroupChoice.EdSearchKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  if Key = VK_RETURN then
  begin
    EdSearch.SelectAll;
    ActSearch.Execute;
  end;
end;

procedure TvisGroupChoice.FormShow(Sender: TObject);
begin
  ActSearch.Execute;
end;

end.

