unit uviwuapackageselect;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  StdCtrls, ButtonPanel, ActnList, sogrid,superobject, VirtualTrees;

type

  { TVisWUAPackageSelect }

  TVisWUAPackageSelect = class(TForm)
    ActSearch: TAction;
    ActionList1: TActionList;
    Button1: TButton;
    Button2: TButton;
    ButtonPanel1: TButtonPanel;
    cbWUCritical: TCheckBox;
    cbWUImportant: TCheckBox;
    cbWULow: TCheckBox;
    cbWUModerate: TCheckBox;
    cbWUOther: TCheckBox;
    CBWUProductsShowAll: TCheckBox;
    EdTitle: TMemo;
    EdKeywords: TEdit;
    GridWinproducts: TSOGrid;
    GridWinUpdates: TSOGrid;
    GridWinClassifications: TSOGrid;
    Label1: TLabel;
    Label2: TLabel;
    EdDescription: TMemo;
    Panel1: TPanel;
    Panel15: TPanel;
    Panel16: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
    Splitter1: TSplitter;
    Splitter2: TSplitter;
    TimerWUAFilterWinUpdates: TTimer;
    procedure ActSearchExecute(Sender: TObject);
    procedure ActSearchUpdate(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure CBWUProductsShowAllClick(Sender: TObject);
    procedure EdKeywordsChange(Sender: TObject);
    procedure FormClick(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormShow(Sender: TObject);
    procedure GridWinUpdatesChange(Sender: TBaseVirtualTree; Node: PVirtualNode
      );
    procedure TimerWUAFilterWinUpdatesTimer(Sender: TObject);
  private
    function FilterWinUpdates(winupdates: ISuperObject): ISuperObject;
    procedure RefreshFilterData(Sender: TObject);
    { private declarations }
  public
    { public declarations }
    WindowsUpdates:ISUperObject;
    WindowsUpdatesFilter:String;
    function BuildWindowsUpdatesFilter:String;
    function SelectedSeverities: ISUperObject;

  end;

var
  VisWUAPackageSelect: TVisWUAPackageSelect;

implementation
uses waptcommon, uVisWAPTWUAProducts,soutils;
{$R *.lfm}

{ TVisWUAPackageSelect }

procedure TVisWUAPackageSelect.RefreshFilterData(Sender: TObject);
begin
  GridWinClassifications.Data := WAPTServerJsonGet('api/v2/windows_updates_classifications',[])['result'];
  GridWinproducts.Data := WAPTServerJsonGet('api/v2/windows_products?selected=1',[])['result'];
end;

procedure TVisWUAPackageSelect.Button1Click(Sender: TObject);
begin
  with TVisWUAProducts.Create(self) do
  try
    if ShowModal = mrOk then
      RefreshFilterData(Self);
  finally
    Free;
  end;
end;

procedure TVisWUAPackageSelect.CBWUProductsShowAllClick(Sender: TObject);
begin
  RefreshFilterData(Sender);
end;

procedure TVisWUAPackageSelect.EdKeywordsChange(Sender: TObject);
begin
  TimerWUAFilterWinUpdates.Enabled:=False;
  TimerWUAFilterWinUpdates.Enabled:=True;
end;

procedure TVisWUAPackageSelect.ActSearchUpdate(Sender: TObject);
var
  RemoteFilterUpdated:Boolean;
begin
  RemoteFilterUpdated := BuildWindowsUpdatesFilter <> WindowsUpdatesFilter;
  ActSearch.Enabled := RemoteFilterUpdated;
  if RemoteFilterUpdated and (WindowsUpdates<>Nil) then
  begin
    WindowsUpdates := Nil;
    GridWinUpdates.Data := Nil;
  end;
end;

procedure TVisWUAPackageSelect.ActSearchExecute(Sender: TObject);
begin
  try
    Screen.Cursor:=crHourGlass;
    WindowsUpdatesFilter:=BuildWindowsUpdatesFilter;
    WindowsUpdates := WAPTServerJsonGet('api/v2/windows_updates?%s',[WindowsUpdatesFilter])['result'];
    GridWinUpdates.Data := FilterWinUpdates(WindowsUpdates);
  finally
    Screen.Cursor:=crDefault;
  end;
end;

procedure TVisWUAPackageSelect.FormClick(Sender: TObject);
begin
  TimerWUAFilterWinUpdatesTimer(sender);
end;

procedure TVisWUAPackageSelect.FormCloseQuery(Sender: TObject;
  var CanClose: boolean);
begin
  CanClose := (ModalResult = mrCancel) or ((GridWinUpdates.Focused or ButtonPanel1.OKButton.Focused) and (GridWinUpdates.SelectedCount>0));
end;

procedure TVisWUAPackageSelect.FormShow(Sender: TObject);
begin
  RefreshFilterData(Self);
end;

procedure TVisWUAPackageSelect.GridWinUpdatesChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  if GridWinUpdates.FocusedRow <> Nil then
  begin
    EdTitle.Lines.Text := GridWinUpdates.FocusedRow.S['title'];
    EdDescription.Lines.Text := GridWinUpdates.FocusedRow.S['description'];
  end
  else
  begin
    EdTitle.Lines.Clear;
    EdDescription.Lines.Clear;
  end;
end;

procedure TVisWUAPackageSelect.TimerWUAFilterWinUpdatesTimer(Sender: TObject);
begin
  TimerWUAFilterWinUpdates.Enabled:=False;
  GridWinUpdates.Data := FilterWinUpdates(WindowsUpdates);
end;

function MatchKeywords(Txt,Keywords:String):Boolean;
var
  tok:String;
begin
  Result := True;
  Txt := Trim(LowerCase(txt));
  if Txt = '' then
  begin
    Result := False;
    Exit;
  end;

  Keywords:= trim(LowerCase(keywords));
  while Keywords<>'' do
  begin
    tok := StrToken(Keywords,' ');
    if (tok <> '') and (pos(tok,Txt) = 0) then
    begin
      Result := False;
      Exit;
    end;
  end;
end;

function TVisWUAPackageSelect.FilterWinUpdates(winupdates: ISuperObject): ISuperObject;
var
  winupdate,severities:ISuperObject;
  productid: String;
  accept: boolean;
begin
  Screen.Cursor:=crHourGlass;
  try
    result := TSuperObject.Create(stArray);
    if (winupdates = Nil) then exit;
    severities := SelectedSeverities;

    for winupdate in Winupdates do
    begin
      accept := (severities.AsArray.Length=0) or StrIn(winupdate.S['msrc_severity'],severities);
      accept := accept and ((EdKeywords.Text = '') or (MatchKeywords(winupdate.S['title'] + ' ' +winupdate.S['description'],EdKeywords.Text)));
      if accept then
        Result.AsArray.Add(winupdate);
    end;

  finally
    Screen.Cursor:=crDefault;
  end
end;

function SOColumnExtract(soarray:ISuperObject;fieldname:String):ISuperObject;
var r,cell:ISuperObject;
begin
  result := TSuperObject.Create(stArray);
  for r in soarray do
  begin
    cell := r[fieldname];
    if cell<>Nil then
        result.AsArray.Add(cell);
  end;
end;

function TVisWUAPackageSelect.BuildWindowsUpdatesFilter: String;
var
  filter:ISuperObject;
begin
  filter := TSuperObject.Create(stArray);
  if GridWinproducts.SelectedCount>0 then
    Filter.AsArray.Add('products='+join(',',SOColumnExtract(GridWinproducts.SelectedRows,'product')))
  else
    Filter.AsArray.Add('selected_products=1');

  if GridWinClassifications.SelectedCount>0 then
    Filter.AsArray.Add('update_classifications='+join(',',SOColumnExtract(GridWinClassifications.SelectedRows,'id')))
  else
    //critical and security
    Filter.AsArray.Add('update_classifications=e6cf1350-c01b-414d-a61f-263d14d133b4,0fa1201d-4330-4fa8-8ae9-b877473b6441');

  result := join('&',filter);
end;

function TVisWUAPackageSelect.SelectedSeverities: ISUperObject;
begin
  Result := TSuperObject.Create(stArray);
  if cbWUCritical.Checked then
    Result.AsArray.Add('Critical');
  if cbWUImportant.Checked then
    Result.AsArray.Add('Important');
  if cbWUModerate.Checked then
    Result.AsArray.Add('Moderate');
  if cbWULow.Checked then
    Result.AsArray.Add('Low');
  if cbWUOther.Checked then
    Result.AsArray.Add('null');
end;



end.

