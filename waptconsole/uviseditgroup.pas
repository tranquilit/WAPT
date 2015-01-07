unit uviseditgroup;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  Buttons, StdCtrls, sogrid,superobject, DefaultTranslator;

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
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Panel4: TPanel;
  private
    FGroup: String;
    members:ISuperobject;
    procedure SetGroup(AValue: String);
    { private declarations }
  public
    { public declarations }
    property Group : String read FGroup write SetGroup;
  end;

var
  VisEditGroup: TVisEditGroup;

implementation
uses tiscommon,waptcommon;
{$R *.lfm}

{ TVisEditGroup }

procedure TVisEditGroup.SetGroup(AValue: String);
begin
  if FGroup=AValue then Exit;
  FGroup:=AValue;
  members :=  WAPTServerJsonGet('/hosts_by_group/'+Fgroup, [],
    UseProxyForServer,
    waptServerUser, waptServerPassword);
  EdGroup.Text:=Fgroup;
  GridHosts.Data := members;
  GridHosts.Header.AutoFitColumns(False);
end;

end.

