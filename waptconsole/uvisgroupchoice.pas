unit uvisgroupchoice;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, ButtonPanel, ActnList, sogrid, superobject, dmwaptpython;

type

  { TvisGroupChoice }

  TvisGroupChoice = class(TForm)
    ActSearchGroups: TAction;
    ActionList1: TActionList;
    butSearchGroups: TButton;
    ButtonPanel1: TButtonPanel;
    EdSearch: TEdit;
    groupGrid: TSOGrid;
    Label2: TLabel;
    procedure ActSearchGroupsExecute(Sender: TObject);
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

procedure TvisGroupChoice.ActSearchGroupsExecute(Sender: TObject);
var
  expr, res: UTF8String;
  groups: ISuperObject;
begin
  expr := format('mywapt.search("%s".split(),section_filter="group")', [EdSearch.Text]);
  groups := DMPython.RunJSON(expr);
  groupGrid.Data := groups;
  groupGrid.Header.AutoFitColumns(False);
end;

end.

