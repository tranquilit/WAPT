unit uviseditgroup;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  Buttons, StdCtrls, sogrid;

type

  { TVisEditGroup }

  TVisEditGroup = class(TForm)
    BitBtn2: TBitBtn;
    Button5: TButton;
    Eddescription: TLabeledEdit;
    EdGroup: TLabeledEdit;
    GridDepends: TSOGrid;
    GridHosts: TSOGrid;
    GridPackages: TSOGrid;
    Panel4: TPanel;
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisEditGroup: TVisEditGroup;

implementation

{$R *.lfm}

end.

