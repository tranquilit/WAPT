unit uVisWUAGroup;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ComCtrls,
  ExtCtrls, StdCtrls, Buttons, Menus, ActnList, superobject,sogrid, VirtualTrees;

type

  { TVisWUAGroup }

  TVisWUAGroup = class(TForm)
    ActWUALoadGroup: TAction;
    ActWUALoadUpdates: TAction;
    ActionList1: TActionList;
    ActionsImages: TImageList;
    ActWUAAllowSelectedUpdates: TAction;
    ActWUADownloadSelectedUpdate: TAction;
    ActWUAForbidSelectedUpdates: TAction;
    ActWUAProductAllow: TAction;
    ActWUAProductAllowSeverity: TAction;
    ActWUAProductForbid: TAction;
    ActWUAProductForbidSeverity: TAction;
    ActWUAProductHide: TAction;
    ActWUAProductShow: TAction;
    ActWUAResetSelectedUpdates: TAction;
    ActWUASaveUpdatesGroup: TAction;
    BitBtn6: TBitBtn;
    ButAddPackages: TBitBtn;
    ButAddPackages1: TBitBtn;
    cbWUCritical: TCheckBox;
    cbWUImportant: TCheckBox;
    cbWULow: TCheckBox;
    cbWUModerate: TCheckBox;
    cbWUOther: TCheckBox;
    ComboBox1: TComboBox;
    EdWUAGroupName: TEdit;
    EdWUAGroupVersion: TEdit;
    EdWUAGroupDescription: TEdit;
    GridForbiddenWU: TSOGrid;
    GridWinproducts: TSOGrid;
    GridWUUpdates: TSOGrid;
    GridAllowedWU: TSOGrid;
    ImageList1: TImageList;
    Label1: TLabel;
    Label16: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    MenuItem58: TMenuItem;
    MenuItem59: TMenuItem;
    MenuItem60: TMenuItem;
    MenuItem61: TMenuItem;
    MenuItem63: TMenuItem;
    MenuItem64: TMenuItem;
    MenuItem65: TMenuItem;
    MenuItem66: TMenuItem;
    MenuItem67: TMenuItem;
    MenuItem68: TMenuItem;
    MenuItem69: TMenuItem;
    Z: TPageControl;
    panbaswinupdates: TPanel;
    Panel14: TPanel;
    Panel15: TPanel;
    Panel16: TPanel;
    Panel17: TPanel;
    panhautwinupdates: TPanel;
    PopupWUAProducts: TPopupMenu;
    PopupWUAUpdates: TPopupMenu;
    Splitter6: TSplitter;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    TimerWUAFilterWinUpdates: TTimer;
    wupanleft: TPanel;
    wupanright: TPanel;
    procedure ActWUAAllowSelectedUpdatesExecute(Sender: TObject);
    procedure ActWUAForbidSelectedUpdatesExecute(Sender: TObject);
    procedure ActWUALoadGroupExecute(Sender: TObject);
    procedure ActWUASaveUpdatesGroupUpdate(Sender: TObject);
    procedure EdWUAGroupNameExit(Sender: TObject);
    procedure EdWUAGroupNameKeyPress(Sender: TObject; var Key: char);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure GridWinproductsChange(Sender: TBaseVirtualTree; Node: PVirtualNode
      );
    procedure GridWinUpdatesGetImageIndex(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: Integer);
    procedure TimerWUAFilterWinUpdatesTimer(Sender: TObject);
    procedure cbWUCriticalClick(Sender: TObject);
    procedure CBWUProductsShowAllClick(Sender: TObject);
    procedure ActWUADownloadSelectedUpdateUpdate(Sender: TObject);
    procedure ActWUALoadUpdatesUpdate(Sender: TObject);
  private
    FWUAGroup: String;
    function SelectedSeverities: ISUperObject;
    procedure SetWUAGroup(AValue: String);
    { private declarations }
    function FilterWinProducts(products: ISuperObject): ISuperObject;
    function FilterWinUpdates(winupdates: ISuperObject): ISuperObject;
  public
    { public declarations }
    isNew:Boolean;
    WUAProducts,WUAWinupdates,WUAGroupRules : ISuperObject;
    WUARulesModified:Boolean;
    property WUAGroup:String read FWUAGroup write SetWUAGroup;
    function WinUpdateStatus(wupdate:ISuperObject):String;
  end;

var
  VisWUAGroup: TVisWUAGroup;

implementation
uses waptcommon,soutils;

{$R *.lfm}

function TVisWUAGroup.FilterWinProducts(products: ISuperObject): ISuperObject;
var
  wproduct: ISuperObject;
  accept: boolean;
begin
  Result := TSuperObject.Create(stArray);
  if (products = nil) or (products.AsArray = Nil) then
    Exit;
  for wproduct in products do
  begin
    Accept := True; //CBWUProductsShowAll.Checked or wproduct.B['selected'];
    if accept then
      Result.AsArray.Add(wproduct);
  end;
end;

function TVisWUAGroup.FilterWinUpdates(winupdates: ISuperObject): ISuperObject;
var
  winupdate,selection,severities,product:ISuperObject;
  productid: String;
  accept: boolean;
begin
  Screen.Cursor:=crHourGlass;
  try
    result := TSuperObject.Create(stArray);
    selection := TSuperObject.Create(stArray);
    for product in GridWinproducts.SelectedRows do
      selection.AsArray.Add(product.S['product']);

    severities := SelectedSeverities;

    for winupdate in Winupdates do
    begin
      productid := winupdate.S['categories.Product'];
      accept := (severities.AsArray.Length=0) or StrIn(winupdate.S['msrc_severity'],severities);
      accept := accept and ((selection.AsArray.Length=0) or StrIn(productid,selection));

      if accept then
        Result.AsArray.Add(winupdate);
    end;


  finally
    Screen.Cursor:=crDefault;
  end
end;

function TVisWUAGroup.WinUpdateStatus(wupdate: ISuperObject): String;
var
  rules:ISuperObject;
begin
  // sort by product, severity, update_id.  None last...
  //rules := SortByFields(WUAGroupRules,['product_id','severity',
end;

procedure TVisWUAGroup.cbWUCriticalClick(Sender: TObject);
begin
  TimerWUAFilterWinUpdatesTimer(sender);
end;

procedure TVisWUAGroup.CBWUProductsShowAllClick(Sender: TObject);
begin
  GridWinproducts.Data := FilterWinProducts(WUAProducts);
end;

procedure TVisWUAGroup.TimerWUAFilterWinUpdatesTimer(Sender: TObject);
begin
  TimerWUAFilterWinUpdates.Enabled:=False;
  GridWUUpdates.Data := FilterWinUpdates(WUAWinupdates);
end;

procedure TVisWUAGroup.ActWUAForbidSelectedUpdatesExecute(Sender: TObject);
begin
  GridAllowedWU.DeleteRows(GridWUUpdates.SelectedRows);
  GridForbiddenWU.AddRows(GridWUUpdates.SelectedRows);
end;

procedure TVisWUAGroup.ActWUALoadGroupExecute(Sender: TObject);
var
  wsus_rules,item : ISuperObject;
begin
  if FWUAGroup<>'' then
  begin
    EdWUAGroupName.Text:=FWUAGroup;
    EdWUAGroupDescription.Text := '';
    WUARulesModified:=False;
  end
  else
  begin
    EdWUAGroupName.Text:=FWUAGroup;
    EdWUAGroupDescription.Text := '';
    WUARulesModified:=False;
  end;
end;

procedure TVisWUAGroup.ActWUADownloadSelectedUpdateUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled:=GridWUUpdates.SelectedCount>0;
end;

procedure TVisWUAGroup.ActWUAAllowSelectedUpdatesExecute(Sender: TObject);
begin
  GridForbiddenWU.DeleteRows(GridWUUpdates.SelectedRows);
  GridAllowedWU.AddRows(GridWUUpdates.SelectedRows);
end;

procedure TVisWUAGroup.ActWUALoadUpdatesUpdate(Sender: TObject);
begin
  ActWUALoadUpdates.Enabled:=GridWinproducts.SelectedCount>0;
end;

function TVisWUAGroup.SelectedSeverities:ISUperObject;
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

procedure TVisWUAGroup.ActWUASaveUpdatesGroupUpdate(Sender: TObject);
begin
  ActWUASaveUpdatesGroup.Enabled:= (WUAGroup<>'') and (WUARulesModified or EdWUAGroupDescription.Modified);
end;

procedure TVisWUAGroup.EdWUAGroupNameExit(Sender: TObject);
begin
  WUAGroup:=EdWUAGroupName.Text;
end;

procedure TVisWUAGroup.EdWUAGroupNameKeyPress(Sender: TObject; var Key: char);
begin
  if key=#13 then
  begin
    WUAGroup:=EdWUAGroupName.Text;
    EdWUAGroupName.SelectAll;
  end;
end;

procedure TVisWUAGroup.FormCreate(Sender: TObject);
begin
  Screen.Cursor:=crHourGlass;
  try
    WUAGroup:='default';
  finally
    Screen.Cursor:=crdefault;
  end;
end;

procedure TVisWUAGroup.FormShow(Sender: TObject);
begin
  GridWinproducts.Data := FilterWinproducts(WUAProducts);
  GridWUUpdates.Data := FilterWinUpdates(WUAWinupdates);
end;

procedure TVisWUAGroup.GridWinproductsChange(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
begin
  GridWUUpdates.Data := Nil;
  TimerWUAFilterWinUpdates.Enabled:=False;
  TimerWUAFilterWinUpdates.Enabled:=True;
end;

procedure TVisWUAGroup.GridWinUpdatesGetImageIndex(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: Boolean; var ImageIndex: Integer);
var
  row: ISuperObject;
begin
  if Column = 0 then
  begin
    row := (Sender as TSOGrid).GetNodeSOData(Node);
    case row.S['status'] of
      'ALLOWED': ImageIndex := 0;
      'FORBIDDEN': ImageIndex := 8;
    else
      ImageIndex := -1;
    end;
  end;
end;

procedure TVisWUAGroup.SetWUAGroup(AValue: String);
begin
  if FWUAGroup=AValue then Exit;
  FWUAGroup:=AValue;
  ActWUALoadGroup.Execute;
end;


end.

