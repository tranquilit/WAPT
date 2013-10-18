unit uvisgroupchoice;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, ButtonPanel;

type

  { TvisGroupChoice }

  TvisGroupChoice = class(TForm)
    ButtonPanel1: TButtonPanel;
    CheckGroup1: TCheckGroup;
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  visGroupChoice: TvisGroupChoice;

implementation

{$R *.lfm}

end.

