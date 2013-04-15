unit uwapttray;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, BufDataset, FileUtil, Forms, Controls, Graphics, Dialogs,
  ExtCtrls, Menus, ActnList, StdCtrls, ValEdit, ComCtrls;

type

  { TVisWAPTTray }

  TVisWAPTTray = class(TForm)
    pages: TPageControl;
    pgStatus: TTabSheet;
    TabSheet2: TTabSheet;
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisWAPTTray: TVisWAPTTray;

implementation

uses waptcommon, superobject,tiscommon,Process,LCLIntf;

{$R *.lfm}

{ TVisWAPTTray }


end.

