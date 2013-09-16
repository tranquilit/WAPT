unit uvislogin;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons, ButtonPanel;

type

  { TVisLogin }

  TVisLogin = class(TForm)
    ButtonPanel1: TButtonPanel;
    edPassword: TEdit;
    edUser: TEdit;
    edWaptServerName: TEdit;
    Label1: TLabel;
    laPassword: TLabel;
    laPassword1: TLabel;
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisLogin: TVisLogin;

implementation

{$R *.lfm}

end.

