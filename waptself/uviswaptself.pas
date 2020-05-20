unit uVisWaptSelf;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, RTTICtrls, Forms, Controls, Graphics, Dialogs,
  ExtCtrls, EditBtn, StdCtrls, Buttons, ActnList, BCListBox,
  BCMaterialDesignButton, BCLabel, FXMaterialButton, IdAuthentication,
  superobject, waptcommon, sogrid, uWAPTPollThreads, VirtualTrees,
  ImgList, ComCtrls, Menus, uFrmPackage, uFrmDetailsPackage, lmessages,uFrmNextPrevious;

type
  { TThreadGetAllIcons }
  TThreadGetAllIcons = class(TThread)
  private
    FOnNotifyEvent: TNotifyEvent;
    procedure NotifyListener; Virtual;
    procedure SetOnNotifyEvent(AValue: TNotifyEvent);
  public
    tmpLstIcons: TStringList;
    lastIconDownloaded: AnsiString;
    ListPackages: ISuperObject;
    FlowPanel: TFlowPanel;
    property OnNotifyEvent: TNotifyEvent read FOnNotifyEvent write SetOnNotifyEvent;
    constructor Create(aNotifyEvent: TNotifyEvent; AllPackages: ISuperObject; aFlowPanel: TFlowPanel);
    procedure Execute; override;
  end;

  { TVisWaptSelf }

  TVisWaptSelf = class(TForm)
    ActCancelTask: TAction;
    ActHideDetailsClick: TAction;
    ActHideTaskBar: TAction;
    ActUpgradeAll: TAction;
    ActUpdateCatalogue: TAction;
    ActResizeFlowPackages: TAction;
    ActShowTaskBar: TAction;
    ActUpdatePackagesList: TAction;
    ActTriggerSearch: TAction;
    ActUnselectAllKeywords: TAction;
    ActSearchPackages: TAction;
    ActionList1: TActionList;
    BtnCancelTasks: TFXMaterialButton;
    BtnHideDetails: TFXMaterialButton;
    BtnHideTaskBar: TFXMaterialButton;
    BtnShowTaskBar: TFXMaterialButton;
    BtnUpdateCatalogue: TFXMaterialButton;
    BtnUpgradeAll: TFXMaterialButton;
    ComboBoxCategories: TComboBox;
    EdSearch: TEditButton;
    FrmDetailsPackageInPanel: TFrmDetailsPackage;
    ImageCrossSearch: TImage;
    LabCategories: TLabel;
    LogoSettings: TImage;
    ImageLogo: TImage;
    ImageLogoDetails: TImage;
    ImageLogoTaskBar: TImage;
    Panel1: TPanel;
    PanelImageCrossSearch: TPanel;
    RadioSortByNameAZ: TRadioButton;
    RadioSortByNameZA: TRadioButton;
    SortBy: TRadioGroup;
    Panel3: TPanel;
    Panel5: TPanel;
    Panel8: TPanel;
    Panel9: TPanel;
    PicLogo: TImage;
    LabelNoResult: TLabel;
    FlowPackages: TFlowPanel;
    ImageListTaskStatus: TImageList;
    PanCategories: TPanel;
    Panel2: TPanel;
    Packages: TRadioGroup;
    RadioShowInstalled: TRadioButton;
    RadioShowAll: TRadioButton;
    RadioSortByDateDescending: TRadioButton;
    RadioShowUpgradable: TRadioButton;
    RadioShowNotInstalled: TRadioButton;
    RadioSortByDateAscending: TRadioButton;
    ScrollBoxDetails: TScrollBox;
    TaskBarPanel: TPanel;
    Panel4: TPanel;
    Panel6: TPanel;
    ProgressBarTaskRunning: TProgressBar;
    ScrollBoxPackages: TScrollBox;
    SOGridTasks: TSOGrid;
    Splitter1: TSplitter;
    StaticText1: TStaticText;
    StaticText2: TStaticText;
    DetailsBarPanel: TPanel;
    TimerPreviousFrames: TTimer;
    TimerNextFrames: TTimer;
    TimerSearch: TTimer;

    procedure ActCancelTaskExecute(Sender: TObject);
    procedure ActCancelTaskUpdate(Sender: TObject);
    procedure ActHideTaskBarExecute(Sender: TObject);
    procedure ActResizeFlowPackagesExecute(Sender: TObject);
    procedure ActSearchPackagesExecute(Sender: TObject);
    procedure ActShowAllClearFilters(Sender: TObject);
    procedure ActShowInstalled(Sender: TObject);
    procedure ActShowNotInstalled(Sender: TObject);
    procedure ActShowTaskBarExecute(Sender: TObject);
    procedure ActShowUpgradable(Sender: TObject);
    procedure ActTriggerSearchExecute(Sender: TObject);
    procedure ActUpdateCatalogueExecute(Sender: TObject);
    procedure ActUpdatePackagesListExecute(Sender: TObject);
    procedure ActUpgradeAllExecute(Sender: TObject);
    procedure ComboBoxCategoriesChange(Sender: TObject);
    procedure DetailsBarPanelPaint(Sender: TObject);
    procedure EdSearchButtonClick(Sender: TObject);
    procedure EdSearchChange(Sender: TObject);
    procedure EdSearchKeyPress(Sender: TObject; var Key: char);
    procedure FormCreate(Sender: TObject);
    procedure FormResize(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure ActHideDetailsClickExecute(Sender: TObject);
    procedure ImageCrossSearchClick(Sender: TObject);
    procedure ImageCrossSearchMouseEnter(Sender: TObject);
    procedure ImageCrossSearchMouseLeave(Sender: TObject);
    procedure ImageLogoClick(Sender: TObject);
    procedure ImageLogoMouseEnter(Sender: TObject);
    procedure ImageLogoMouseLeave(Sender: TObject);
    procedure ImageWAPTClick(Sender: TObject);
    procedure ImageLogoTaskBarClick(Sender: TObject);
    procedure ImageLogoOnMouseEnter(Sender: TObject);
    procedure ImageLogoOnMouseLeave(Sender: TObject);
    procedure ImageWAPTMouseEnter(Sender: TObject);
    procedure ImageWAPTMouseLeave(Sender: TObject);
    procedure LabOfficialWebsiteClick(Sender: TObject);
    procedure LabOfficialWebsiteMouseEnter(Sender: TObject);
    procedure LabOfficialWebsiteMouseLeave(Sender: TObject);
    procedure LogoSettingsClick(Sender: TObject);
    procedure LogoSettingsMouseEnter(Sender: TObject);
    procedure LogoSettingsMouseLeave(Sender: TObject);
    procedure Panel6Resize(Sender: TObject);
    procedure RadioSortByDateAscendingClick(Sender: TObject);
    procedure RadioSortByDateDescendingClick(Sender: TObject);
    procedure RadioSortByNameAZClick(Sender: TObject);
    procedure RadioSortByNameZAClick(Sender: TObject);
    procedure SOGridTasksGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: Integer;
      var ImageList: TCustomImageList);
    procedure TaskBarPanelPaint(Sender: TObject);
    procedure TimerNextFramesTimer(Sender: TObject);
    procedure TimerPreviousFramesTimer(Sender: TObject);
    procedure TimerSearchTimer(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormClose(Sender: TObject);
  private
    PrevWndProc: TWndMethod;
    ShowOnlyUpgradable: Boolean;
    ShowOnlyInstalled: Boolean;
    ShowOnlyNotInstalled: Boolean;
    SortByDateAsc:Boolean;
    SortByName:Boolean;
    SortByNameAZ:Boolean;
    WAPTServiceRunning:Boolean;
    LastTaskIDOnLaunch:integer;
    CurrentTaskID:integer;

    LastNumberOfFrame:integer;

    LstIcons: TStringList;
    LstTasks: TStringList;
    FAllPackages: ISuperObject;

    FThreadGetAllIcons: TThreadGetAllIcons;

    FramePage : integer;
    NumberOfFrames: Integer;

    function GetAllPackages: ISuperObject;       
    procedure DownloadAllPackageIcons;
    procedure LoadIcons;
    procedure OnUpgradeTriggeredAllPackages(Sender : TObject);

    procedure OnUpgradeAllIcons(Sender : TObject);

    //Polling thread
    procedure OnCheckTasksThreadNotify(Sender: TObject);
    procedure OnCheckEventsThreadNotify(Sender: TObject);
    procedure ChangeProgressionFrmPackageOnEvent(LastEvent: ISuperObject);

    //Functions for generate frames
    function IsValidPackage(package : ISuperObject):Boolean;
    function IsValidFilter(package : ISuperObject):Boolean;
    function IsValidCategory(package : ISuperObject):Boolean;
    function SelectedAreOnlyPending: Boolean;
    function CanNext(): Boolean;

    function RemoveAccent(const AText : String) : string;
    function GetAllPackagesSorted(Pck : ISuperObject):ISuperObject;
    function GetAllCategories(Pck : ISuperObject):TStringList;
    property AllPackages:ISuperObject read GetAllPackages write FAllPackages;
    procedure EventsScrollBar(var TheMessage: TLMessage);
    procedure AddFrameOnFlowPackages(Pck : ISuperObject);
  public
    CheckTasksThread: TCheckAllTasksThread;
    CheckEventsThread: TCheckEventsThread;
    procedure ChangeIconMinusByPlusOnFrames();
    procedure NextFrames();
    procedure PreviousFrames();
    function GoodSizeForScreen(ASize : integer):integer;
  end;

var
  VisWaptSelf: TVisWaptSelf;


implementation
uses LCLIntf, LCLType, soutils, strutils, uWaptSelfRes, IniFiles, IdHTTP, LConvEncoding, uVisSettings, LCLTranslator, math, uDMWaptSelf;
{$R *.lfm}

{ TVisWaptSelf }

procedure TVisWaptSelf.ActSearchPackagesExecute(Sender: TObject);
var
  Pck:ISuperObject;
  AFrmNextPrevious : TFrmNextPrevious;
  idx:Integer;
begin
  try
    TimerSearch.Enabled:=False;
    Screen.Cursor:=crHourGlass;
    FlowPackages.DisableAlign;

    for idx := FlowPackages.ControlCount-1 downto 0 do
      FlowPackages.Controls[idx].Free;
    FlowPackages.ControlList.Clear;

    LastNumberOfFrame:=0;

    for Pck in AllPackages do
    begin
      if IsValidPackage(Pck) and IsValidFilter(Pck) and IsValidCategory(Pck) then
      begin
        inc(LastNumberOfFrame);
        AddFrameOnFlowPackages(Pck);
        if LastNumberOfFrame=NumberOfFrames then
        Break;
      end;
    end;

    if CanNext() then
    begin
      AFrmNextPrevious:=TFrmNextPrevious.Create(FlowPackages);
      with AFrmNextPrevious do
      begin
        Parent:=FlowPackages;
        Name:='NextPrev';
        LogoPrev.Hide;
        LabPage.Caption:='Page : 1/'+IntToStr(Ceil(AllPackages.AsArray.Length / NumberOfFrames));
      end;
    end;

    FramePage:=1;

    if ShowOnlyUpgradable and (LastNumberOfFrame>=1) then
      BtnUpgradeAll.Show
    else
      BtnUpgradeAll.Hide;

    if (LastNumberOfFrame=0) then
    begin
      LabelNoResult.Show;
      PicLogo.Show;
    end
    else
    begin
      LabelNoResult.Hide;
      PicLogo.Hide;
    end;
  finally
    FlowPackages.EnableAlign;
    Screen.Cursor:=crDefault;
  end;
end;

function TVisWaptSelf.CanNext(): Boolean;
var
  Pck : ISuperObject;
  i : integer;
begin
  i:=0;
  for Pck in AllPackages do
  begin
    if IsValidPackage(Pck) and IsValidFilter(Pck) and IsValidCategory(Pck) then
    begin
      inc(i);
      if (i>LastNumberOfFrame) then
        Exit(True);
    end;
  end;
  Result:=false;
end;

procedure TVisWaptSelf.NextFrames();
var
  Pck:ISuperObject;
  AFrmNextPrevious : TFrmNextPrevious;
  idx:Integer;
begin
  try
    Screen.Cursor:=crHourGlass;
    FlowPackages.DisableAlign;

    for idx := FlowPackages.ControlCount-1 downto 0 do
        FlowPackages.Controls[idx].Free;
    FlowPackages.ControlList.Clear;

    LastNumberOfFrame:=FramePage*NumberOfFrames;
    idx:=0;

    for Pck in AllPackages do
    begin
      inc(idx);
      if (idx>LastNumberOfFrame) and IsValidPackage(Pck) and IsValidFilter(Pck) and IsValidCategory(Pck) then
      begin
        inc(LastNumberOfFrame);
        AddFrameOnFlowPackages(Pck);
        if LastNumberOfFrame=(NumberOfFrames*(FramePage+1)) then
        Break;
      end;
    end;

    inc(FramePage);
    AFrmNextPrevious:=TFrmNextPrevious.Create(FlowPackages);
    with AFrmNextPrevious do
    begin
      Parent:=FlowPackages;
      Name:='NextPrev';
      LabPage.Caption:='Page : '+IntToStr(FramePage)+'/'+IntToStr(Ceil(AllPackages.AsArray.Length / NumberOfFrames));
      if not(CanNext()) then
        LogoNext.Hide;
    end;

  finally
    FlowPackages.EnableAlign;
    Screen.Cursor:=crDefault;
  end;
end;

procedure TVisWaptSelf.PreviousFrames();
var
  Pck:ISuperObject;
  AFrmNextPrevious : TFrmNextPrevious;
  idx,tmp:Integer;
begin
  try
    Screen.Cursor:=crHourGlass;
    FlowPackages.DisableAlign;

    for idx := FlowPackages.ControlCount-1 downto 0 do
      FlowPackages.Controls[idx].Free;
    FlowPackages.ControlList.Clear;

    tmp:=0;

    for Pck in AllPackages do
    begin
      inc(idx);
      if (idx>((FramePage-2)*NumberOfFrames)) and IsValidPackage(Pck) and IsValidFilter(Pck) and IsValidCategory(Pck) then
      begin
        dec(LastNumberOfFrame);
        inc(tmp);
        AddFrameOnFlowPackages(Pck);
        if (tmp=NumberOfFrames) then
          break;
      end;
    end;

    dec(FramePage);

    AFrmNextPrevious:=TFrmNextPrevious.Create(FlowPackages);
    with AFrmNextPrevious do
    begin
      Parent:=FlowPackages;
      Name:='NextPrev';
      LabPage.Caption:='Page : '+IntToStr(FramePage)+'/'+IntToStr(Ceil(AllPackages.AsArray.Length / NumberOfFrames));
      if FramePage<2 then
        LogoPrev.Hide;
    end;

  finally
    FlowPackages.EnableAlign;
    Screen.Cursor:=crDefault;
    ScrollBoxPackages.VertScrollBar.Position:=FlowPackages.Height;
  end;
end;

procedure TVisWaptSelf.ActCancelTaskUpdate(Sender: TObject);
begin
  ActCancelTask.Enabled := (SOGridTasks.SelectedCount>0 ) and (SelectedAreOnlyPending);
  if (ActCancelTask.Enabled) then
    BtnCancelTasks.NormalColor:=$0099542F
  else
    BtnCancelTasks.NormalColor:=clSilver;
end;

procedure TVisWaptSelf.ActHideTaskBarExecute(Sender: TObject);
begin
  TaskBarPanel.Hide;
  FlowPackages.Show;
  Panel6.Show;
end;

procedure TVisWaptSelf.ActResizeFlowPackagesExecute(Sender: TObject);
var
  i,WidthPref: integer;
begin
  if (FlowPackages.Width>ScaleX(350,96)) then
  begin
    WidthPref:=trunc((FlowPackages.Width/(FlowPackages.Width div ScaleX(350,96)))-1);
    for i:=0 to FlowPackages.ControlCount-1 do
    begin
      if (FlowPackages.Controls[i] is TFrmPackage) then
      begin
        (FlowPackages.Controls[i] as TFrmPackage).Width:=WidthPref;
      end
      else
        (FlowPackages.Controls[i] as TFrmNextPrevious).Width:=FlowPackages.Width;
    end;
  end
  else
  begin
    if TaskBarPanel.Showing or DetailsBarPanel.Showing then
    begin
      TaskBarPanel.Hide;
      DetailsBarPanel.Hide;
    end;
  end;
end;

procedure TVisWaptSelf.FormResize(Sender: TObject);
begin
  if (FlowPackages.Showing) and (FlowPackages.Width<=ScaleX(350,96)) then
  begin
    FlowPackages.Hide;
  end;
  if not(FlowPackages.Showing) and (ScrollBoxPackages.Width>ScaleX(350,96)) then
  begin
    FlowPackages.Show;
  end;
  if not(FlowPackages.Showing) and (TaskBarPanel.Showing or DetailsBarPanel.Showing) and (ScrollBoxPackages.Width<=ScaleX(350,96)) then
  begin
    TaskBarPanel.Hide;
    DetailsBarPanel.Hide;
  end;

  if (VisWaptSelf.Height<ScaleY(450,96)) then
    ImageLogoTaskBar.Hide
  else
    ImageLogoTaskBar.Show;

  if (VisWaptSelf.Height<ScaleY(765,96)) then
    Panel3.Hide
  else
    Panel3.Show;
end;

procedure TVisWaptSelf.Panel6Resize(Sender: TObject);
var
  Ratio: Real;
begin
  if (Panel6.Width>0) then
    if (Panel6.Width>ScaleX(650,96)) then
    begin
      PicLogo.AutoSize:=true;
      LabelNoResult.AutoSize:=true;
      LabelNoResult.Width:=ScaleX(486,96);
      LabelNoResult.Height:=ScaleY(50,96);
      LabelNoResult.AdjustFontForOptimalFill;
      PicLogo.Width:=ScaleX(400,96);
      PicLogo.Height:=ScaleY(190,96);
    end
    else
    begin
      Ratio:=Panel6.Width / ScaleX(650,96);
      PicLogo.AutoSize:=false;
      LabelNoResult.AutoSize:=false;
      LabelNoResult.Width:=trunc(ScaleX(486,96)*Ratio);
      LabelNoResult.Height:=trunc(ScaleY(50,96)*Ratio);
      LabelNoResult.AdjustFontForOptimalFill;
      PicLogo.Width:=trunc(ScaleX(400,96)*Ratio);
      PicLogo.Height:=trunc(ScaleY(190,96)*Ratio);
    end
end;

procedure TVisWaptSelf.RadioSortByDateAscendingClick(Sender: TObject);
begin
  SortByDateAsc:=true;
  SortByName:=false;
  ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.RadioSortByDateDescendingClick(Sender: TObject);
begin
  SortByDateAsc:=false;
  SortByName:=false;
  ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.RadioSortByNameAZClick(Sender: TObject);
begin
  SortByName:=true;
  SortByNameAZ:=true;
  ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.RadioSortByNameZAClick(Sender: TObject);
begin
  SortByName:=true;
  SortByNameAZ:=false;
  ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.ActShowTaskBarExecute(Sender: TObject);
begin
  if (TaskBarPanel.Showing) then
    TaskBarPanel.Hide
  else
    TaskBarPanel.Show;
  if (FlowPackages.Showing) and (FlowPackages.Width<ScaleX(350,96)) then
  begin
    FlowPackages.Hide;
    Panel6.Hide;
  end;
  if not(FlowPackages.Showing) and (ScrollBoxPackages.Width>=ScaleX(350,96)) then
  begin
    FlowPackages.Show;
    Panel6.Show;
  end;
end;

procedure TVisWaptSelf.DetailsBarPanelPaint(Sender: TObject);
begin
  if (TaskBarPanel.Showing) then
    TaskBarPanel.Hide;
  if (FlowPackages.Showing) and (FlowPackages.Width<ScaleX(350,96)) then
  begin
    FlowPackages.Hide;
    Panel6.Hide;
  end;
end;

procedure TVisWaptSelf.TaskBarPanelPaint(Sender: TObject);
begin
  DetailsBarPanel.Hide;
  ChangeIconMinusByPlusOnFrames();
  BtnShowTaskBar.Caption:=rsTaskBar;
end;

procedure TVisWaptSelf.TimerNextFramesTimer(Sender: TObject);
begin
  TimerNextFrames.Enabled:=False;
  NextFrames();
end;

procedure TVisWaptSelf.TimerPreviousFramesTimer(Sender: TObject);
begin
  TimerPreviousFrames.Enabled:=False;
  PreviousFrames();
end;

procedure TVisWaptSelf.ActCancelTaskExecute(Sender: TObject);
var
 Task : ISuperObject;
 i : integer;
 AFrmPackage: TFrmPackage;
begin
  for Task in SOGridTasks.SelectedRows do
  begin
    for i:=0 to FlowPackages.ControlCount-1 do
    begin
      AFrmPackage:=FlowPackages.Controls[i] as TFrmPackage;
      if (AFrmPackage.TaskID<>0) and (AFrmPackage.TaskID=Task.I['id']) then
      begin
        AFrmPackage.CancelTask();
        Exit();
      end;
    end;
  end;
end;

procedure TVisWaptSelf.ActShowAllClearFilters(Sender: TObject);
begin
  ShowOnlyNotInstalled:=false;
  ShowOnlyUpgradable:=false;
  ShowOnlyInstalled:=false;
  ActSearchPackages.Execute;
  RadioShowUpgradable.Checked:=false;
  RadioShowInstalled.Checked:=false;
  RadioShowNotInstalled.Checked:=false;
end;

procedure TVisWaptSelf.ActShowInstalled(Sender: TObject);
begin
   ShowOnlyNotInstalled:=false;
   ShowOnlyUpgradable:=false;
   ShowOnlyInstalled:=true;
   RadioShowUpgradable.Checked:=false;
   RadioShowAll.Checked:=false;
   RadioShowNotInstalled.Checked:=false;
   ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.ActShowNotInstalled(Sender: TObject);
begin
   ShowOnlyNotInstalled:=true;
   ShowOnlyUpgradable:=false;
   ShowOnlyInstalled:=false;
   ActSearchPackages.Execute;
   RadioShowUpgradable.Checked:=false;
   RadioShowAll.Checked:=false;
   RadioShowInstalled.Checked:=false;
end;

procedure TVisWaptSelf.ActShowUpgradable(Sender: TObject);
begin
  ShowOnlyNotInstalled:=false;
  ShowOnlyUpgradable:=true;
  ShowOnlyInstalled:=false;
  ActSearchPackages.Execute;
  RadioShowInstalled.Checked:=false;
  RadioShowAll.Checked:=false;
  RadioShowNotInstalled.Checked:=false;
end;

procedure TVisWaptSelf.ActTriggerSearchExecute(Sender: TObject);
begin
  TimerSearch.Enabled:=False;
  TimerSearch.Enabled:=True;
end;

procedure TVisWaptSelf.ActUpdateCatalogueExecute(Sender: TObject);
begin
  DMWaptSelf.JSONGet('update.json');
end;

procedure TVisWaptSelf.ActUpdatePackagesListExecute(Sender: TObject);
begin
  FAllPackages:=Nil;
  ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.ActUpgradeAllExecute(Sender: TObject);
var
 i:integer;
begin
  for i:=0 to FlowPackages.ControlCount-1 do
    if (FlowPackages.Controls[i] is TFrmPackage) then
      (FlowPackages.Controls[i] as TFrmPackage).ActInstallUpgradePackage(Self);
end;

procedure TVisWaptSelf.ComboBoxCategoriesChange(Sender: TObject);
begin
  ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.EdSearchChange(Sender: TObject);
begin
  if (EdSearch.Text='') then
  begin
    ImageCrossSearch.Picture.LoadFromResourceName(HINSTANCE,'LOUPE-15PX');
    TimerSearch.Enabled:=False;
    TimerSearch.Enabled:=True;
  end
  else
  begin
    ImageCrossSearch.Picture.LoadFromResourceName(HINSTANCE,'CROSS_15_PX');
    TimerSearch.Enabled:=False;
    TimerSearch.Enabled:=True;
  end;
end;

procedure TVisWaptSelf.EdSearchButtonClick(Sender: TObject);
begin
  ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.EdSearchKeyPress(Sender: TObject; var Key: char);
begin
  if (Key = #13) and (EdSearch.Text<>'') then
  begin
    EdSearch.SelectAll;
    ActSearchPackages.Execute;
  end;
end;

procedure TVisWaptSelf.SOGridTasksGetImageIndexEx(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: Boolean; var ImageIndex: Integer; var ImageList: TCustomImageList
  );
var
  install_status: ISuperObject;
  propname: String;
  aGrid:TSOGrid;
begin
  aGrid := (Sender as TSOGrid);
  propName:=TSOGridColumn(aGrid.Header.Columns[Column]).PropertyName;

  if propName='install_status' then
  begin
    install_status := aGrid.GetCellData(Node, 'install_status', nil);
    if (install_status <> nil) then
    begin
      case install_status.AsString of
        'RUNNING': ImageIndex := 0;
        'DONE': ImageIndex := 1;
        'PENDING': ImageIndex := 2;
      end;
    end;
  end
end;

procedure TVisWaptSelf.TimerSearchTimer(Sender: TObject);
begin
  TimerSearch.Enabled:=False;
  ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.LoadIcons;
var
  IconsDir : String;
  g : TPicture;
  i : integer;
begin
  IconsDir := GetIconsDir();
  LstIcons := FindAllFiles(IconsDir, '*.png', False);
  LstIcons.OwnsObjects:=True;

  for i:=0 to LstIcons.Count-1 do
  try
    g := Nil;
    g:=TPicture.Create;
    g.LoadFromFile(LstIcons[i]);
    LstIcons.Objects[i]:=g;
    g := Nil;
    LstIcons[i]:=ExtractFileName(LstIcons[i]);
  except
    if Assigned(g) then
      FreeAndNil(g);
  end;
  LstIcons.Sort;
  LstIcons.Sorted := True;
  LstIcons.Duplicates:=dupIgnore;
end;

procedure TVisWaptSelf.FormCreate(Sender: TObject);
var
  PicLogoTmp: TPicture;
begin
  Visible := False;
  if (not ReadWaptConfig(IncludeTrailingPathDelimiter(GetCurrentDir)+'wapt-get.ini')) then
    ReadWaptConfig();
  SortByDateAsc:=false;
  SortByName:=false;
  NumberOfFrames:=Round(80*(96/Screen.PixelsPerInch));

  ShowOnlyInstalled:=false;
  ShowOnlyNotInstalled:=false;
  ShowOnlyUpgradable:=false;

  LstTasks:=TStringList.Create;
  LstTasks.Sorted:=true;
  LstTasks.Duplicates:=dupIgnore;
  CurrentTaskID:=0;

  {$ifdef ENTERPRISE }
  if FileExists(WaptBaseDir+'\templates\waptself-logo.png') then
    PicLogo.Picture.LoadFromFile(WaptBaseDir+'\templates\waptself-logo.png')
  else
    PicLogo.Picture.LoadFromResourceName(HINSTANCE,'SELF-SERVICE-ENTERPRISE-400PX');
  if FileExists(WaptBaseDir+'\templates\waptself-logo.png') then
  begin
    ImageLogo.Picture.LoadFromFile(WaptBaseDir+'\templates\waptself-logo.png');
    PicLogoTmp:=TPicture.Create;
    PicLogoTmp.LoadFromResourceName(HINSTANCE,'SELF-SERVICE-ENTERPRISE-200PX');
    VisWaptSelf.Constraints.MinHeight:=VisWaptSelf.Constraints.MinHeight-PicLogoTmp.Height+ImageLogo.Picture.Height;
    FreeAndNil(PicLogoTmp);
  end
  else
    ImageLogo.Picture.LoadFromResourceName(HINSTANCE,'SELF-SERVICE-ENTERPRISE-200PX');
  {$endif}

  if Screen.PixelsPerInch <> 96 then
  begin
    ImageLogoTaskBar.AutoSize:=false;
    ImageLogoTaskBar.AntialiasingMode:=amOn;
    PicLogo.AutoSize:=false;
    PicLogo.AntialiasingMode:=amOn;
    ImageLogoDetails.AutoSize:=false;
    ImageLogoDetails.AntialiasingMode:=amOn;
    ImageLogo.AutoSize:=false;
    ImageLogo.AntialiasingMode:=amOn;
    LogoSettings.AutoSize:=false;
    LogoSettings.AntialiasingMode:=amOn;
    ImageCrossSearch.AutoSize:=false;
    ImageCrossSearch.AntialiasingMode:=amOn;
    ImageCrossSearch.Stretch:=true;
    BtnShowTaskBar.TextSize:=GoodSizeForScreen(BtnShowTaskBar.TextSize);
    BtnUpdateCatalogue.TextSize:=GoodSizeForScreen(BtnUpdateCatalogue.TextSize);
    BtnUpgradeAll.TextSize:=GoodSizeForScreen(BtnUpgradeAll.TextSize);
    BtnHideDetails.TextSize:=GoodSizeForScreen(BtnHideDetails.TextSize);
    BtnCancelTasks.TextSize:=GoodSizeForScreen(BtnCancelTasks.TextSize);
    BtnHideTaskBar.TextSize:=GoodSizeForScreen(BtnHideTaskBar.TextSize);
    if (Screen.PixelsPerInch>96) then
    begin
      Panel8.Hide;
      Panel3.Hide;
    end;
  end;
  MakeFullyVisible();
  LastTaskIDOnLaunch:=-1;

  if (DMWaptSelf.Token<>'') then
  begin
    Application.ShowMainForm:=true;
    Self.Visible:=true;
  end
  else
    Application.Terminate;

  PrevWndProc:=ScrollBoxPackages.WindowProc;
  ScrollBoxPackages.WindowProc:=@EventsScrollBar;
end;

procedure TVisWaptSelf.FormDestroy(Sender: TObject);
begin
  FreeAndNil(CheckTasksThread);
  FreeAndNil(CheckEventsThread);
  FreeAndNil(FThreadGetAllIcons);
  FreeAndNil(LstIcons);
  FreeAndNil(LstTasks);
end;

procedure TVisWaptSelf.FormShow(Sender: TObject);
var
  ini : TIniFile;
begin
  try
    GetAllPackages();
    DownloadAllPackageIcons();

    ComboBoxCategories.Sorted:=true;
    ComboBoxCategories.Clear;
    ComboBoxCategories.Items.AddStrings(GetAllCategories(AllPackages));
    ComboBoxCategories.ItemIndex:=ComboBoxCategories.Items.IndexOf(rsAllCategories);

    if (DMWaptSelf.Token<>'') then
    begin
      TimerSearch.Enabled:=False;

      if (Application.HasOption('list-upgrade')) then
      begin
        ShowOnlyUpgradable:=true;
        RadioShowAll.Checked:=false;
        RadioShowUpgradable.Checked:=true;
      end
      else if (Application.HasOption('list-install')) then
        begin
          ShowOnlyInstalled:=true;
          RadioShowAll.Checked:=false;
          RadioShowInstalled.Checked:=true;
        end
          else if (Application.HasOption('list-non-install')) then
            begin
              ShowOnlyNotInstalled:=true;
              RadioShowAll.Checked:=false;
              RadioShowInstalled.Checked:=true;
            end;

      if (Application.HasOption('s','search')) then
        EdSearch.Caption:=Application.GetOptionValue('s','search');

      TimerSearch.Enabled:=True;

      //Initialise window with settings in the ini file
      ini:=TIniFile.Create(AppIniFilename);
      try
        if not ini.ValueExists('window','left') then
          LCLIntf.ShowWindow(VisWaptSelf.Handle, SW_MAXIMIZE)
        else
        begin
          Self.left:=ini.ReadInteger('window','left',Self.Left);
          Self.Top:=ini.ReadInteger('window','top',Self.Top);
          Self.Width:=ini.ReadInteger('window','width',Self.Width);
          Self.Height:=ini.ReadInteger('window','height',Self.Height);
          Self.WindowState:=TWindowState(ini.ReadInteger('window','windowstate',Integer(Self.WindowState)));
        end;
      finally
        FreeAndNil(ini);
      end;

      LoadIcons;
      FThreadGetAllIcons:=TThreadGetAllIcons.Create(@OnUpgradeAllIcons,AllPackages,FlowPackages);
      FThreadGetAllIcons.FreeOnTerminate:=true;

      // Check running / pending tasks
      CheckTasksThread := TCheckAllTasksThread.Create(@OnCheckTasksThreadNotify);
      CheckEventsThread := TCheckEventsThread.Create(@OnCheckEventsThreadNotify);
      CheckTasksThread.Start;
      CheckEventsThread.Start;

      EdSearch.Button.Enabled:=False;
      if Screen.PixelsPerInch<>96 then
         SOGridTasks.Header.Height:=trunc((SOGridTasks.Header.MinHeight*Screen.PixelsPerInch)/96)
    end;
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TVisWaptSelf.ActHideDetailsClickExecute(Sender: TObject);
begin
  DetailsBarPanel.Hide;
  FlowPackages.Show;
  Panel6.Show;
  ChangeIconMinusByPlusOnFrames();
end;

procedure TVisWaptSelf.ImageCrossSearchClick(Sender: TObject);
begin
  if (EdSearch.Text<>'') then
  begin
    EdSearch.Text:='';
    ActSearchPackages.Execute;
  end;
end;

procedure TVisWaptSelf.ImageCrossSearchMouseEnter(Sender: TObject);
begin
  if (EdSearch.Text<>'') then
    Screen.Cursor:=crHandPoint;
end;

procedure TVisWaptSelf.ImageCrossSearchMouseLeave(Sender: TObject);
begin
  if (EdSearch.Text<>'') then
    Screen.Cursor:=crDefault;
end;

procedure TVisWaptSelf.ImageLogoClick(Sender: TObject);
begin
  ShowOnlyNotInstalled:=false;
  ShowOnlyUpgradable:=false;
  ShowOnlyInstalled:=false;
  RadioShowUpgradable.Checked:=false;
  RadioShowInstalled.Checked:=false;
  RadioShowNotInstalled.Checked:=false;
  RadioShowAll.Checked:=true;
  SortByDateAsc:=false;
  SortByName:=false;
  SortByNameAZ:=true;
  RadioSortByDateDescending.Checked:=true;
  RadioSortByDateAscending.Checked:=false;
  RadioSortByNameAZ.Checked:=false;
  RadioSortByNameZA.Checked:=false;
  EdSearch.Text:='';
  ComboBoxCategories.ItemIndex:=ComboBoxCategories.Items.IndexOf(rsAllCategories);
  ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.ImageLogoMouseEnter(Sender: TObject);
begin
  Screen.Cursor:=crHandPoint;
end;

procedure TVisWaptSelf.ImageLogoMouseLeave(Sender: TObject);
begin
  Screen.Cursor:=crDefault;
end;

procedure TVisWaptSelf.ImageWAPTClick(Sender: TObject);
begin
  OpenDocument('https://www.tranquil.it/solutions/wapt-deploiement-d-applications/');
end;

procedure TVisWaptSelf.ImageLogoTaskBarClick(Sender: TObject);
begin
  OpenDocument('https://www.tranquil.it');
end;

procedure TVisWaptSelf.ImageLogoOnMouseEnter(Sender: TObject);
begin
  Screen.Cursor := crHandPoint;
end;

procedure TVisWaptSelf.ImageLogoOnMouseLeave(Sender: TObject);
begin
  Screen.Cursor := crDefault;
end;

procedure TVisWaptSelf.ImageWAPTMouseEnter(Sender: TObject);
begin
  Screen.Cursor := crHandPoint;
end;

procedure TVisWaptSelf.ImageWAPTMouseLeave(Sender: TObject);
begin
  Screen.Cursor := crDefault;
end;

procedure TVisWaptSelf.LabOfficialWebsiteClick(Sender: TObject);
begin
  OpenDocument(FrmDetailsPackageInPanel.LabOfficialWebsite.Caption);
end;

procedure TVisWaptSelf.LabOfficialWebsiteMouseEnter(Sender: TObject);
begin
  FrmDetailsPackageInPanel.LabOfficialWebsite.Font.Color:=clHighlight;
  Screen.Cursor := crHandPoint;
end;

procedure TVisWaptSelf.LabOfficialWebsiteMouseLeave(Sender: TObject);
begin
  FrmDetailsPackageInPanel.LabOfficialWebsite.Font.Color:=clDefault;
  Screen.Cursor := crDefault;
end;

procedure TVisWaptSelf.LogoSettingsClick(Sender: TObject);
var
  SettingsDlg : TVisSettings;
  tmpLang : String;
  ini : TIniFile;
begin
  with SettingsDlg do
  begin
    SettingsDlg:=TVisSettings.Create(Self);
    if (ShowModal=mrOK) then
    begin
      if (ComboBoxLang.Items.IndexOf('English')=ComboBoxLang.ItemIndex) then
        tmpLang:='en'
      else
        tmpLang:='fr';
      if (tmpLang<>GetDefaultLang) then
      begin
        ini:=TIniFile.Create(AppIniFilename);
        ini.WriteString('global','language',tmpLang);
        ini.UpdateFile;
        FreeAndNil(ini);
        SetDefaultLang(tmpLang);
        if (tmpLang='en') then
        begin
          ComboBoxCategories.Items.DelimitedText:=ReplaceStr(ComboBoxCategories.Items.DelimitedText,'Toutes',rsAllCategories);
          ComboBoxCategories.ItemIndex:=ComboBoxCategories.Items.IndexOf(rsAllCategories);
          ActSearchPackages.Execute;
        end
        else
        begin
          ComboBoxCategories.Items.DelimitedText:=ReplaceStr(ComboBoxCategories.Items.DelimitedText,'All',rsAllCategories);
          ComboBoxCategories.ItemIndex:=ComboBoxCategories.Items.IndexOf(rsAllCategories);
          ActSearchPackages.Execute;
        end;
      end;
    end;
    FreeAndNil(SettingsDlg);
  end;
end;

procedure TVisWaptSelf.LogoSettingsMouseEnter(Sender: TObject);
begin
  LogoSettings.Picture.LoadFromResourceName(HINSTANCE,'SETTINGS');
end;

procedure TVisWaptSelf.LogoSettingsMouseLeave(Sender: TObject);
begin
  LogoSettings.Picture.LoadFromResourceName(HINSTANCE,'SETTINGS_GREY');
end;

procedure TVisWaptSelf.FormClose(Sender: TObject);
var
  ini : TIniFile;
begin
  CheckTasksThread.Terminate;
  CheckEventsThread.Terminate;
  FThreadGetAllIcons.Terminate;
  //Write save window settings
  ini:=TIniFile.Create(AppIniFilename);
  ini.WriteInteger('window','left',Self.Left);
  ini.WriteInteger('window','top',Self.Top);
  ini.WriteInteger('window','width',Self.Width);
  ini.WriteInteger('window','height',Self.Height);
  ini.WriteInteger('window','windowstate',Integer(Self.WindowState));
  ini.UpdateFile;
  FreeAndNil(ini);
end;

procedure TVisWaptSelf.OnCheckTasksThreadNotify(Sender: TObject);
var
  Tasks,Row,ListDel:ISuperObject;
begin
  try
    Tasks:=(Sender as TCheckAllTasksThread).Tasks;

    if Assigned(Tasks.O['tasks']) then
    begin
      if (LastTaskIDOnLaunch=-1) then
        for Row in Tasks.O['tasks'] do
          if LastTaskIDOnLaunch<Row.I['id'] then
            LastTaskIDOnLaunch:=Row.I['id'];

      ListDel:=SO('[]');

      SOGridTasks.Data:=Tasks.O['tasks'];
      for Row in SOGridTasks.Data do
      begin
        if (Row.I['id']>LastTaskIDOnLaunch) and ((Row.S['classname']='WaptPackageInstall') or (Row.S['classname']='WaptPackageRemove')) then
          begin
            if Row.S['start_date']='' then
              Row.S['install_status']:='PENDING'
            else
              if Row.S['finish_date']='' then
                Row.S['install_status']:='RUNNING'
              else
                Row.S['install_status']:='DONE';
            if Assigned(Row.O['packagenames']) then
              Row.O['packagenames']:=Row.O['packagenames'].AsArray[0];
          end
        else
          ListDel.AsArray.Add(Row);
      end;
      SOGridTasks.DeleteRows(ListDel);
    end;
    WAPTServiceRunning:=(Sender as TCheckAllTasksThread).WaptServiceRunning;
  finally
  end
end;

procedure TVisWaptSelf.ChangeProgressionFrmPackageOnEvent(LastEvent: ISuperObject);
var
  i:integer;
  AFrmPackage:TFrmPackage;
begin
  for i:=0 to FlowPackages.ControlCount-1 do
  begin
    if (FlowPackages.Controls[i] is TFrmPackage) then
    begin
      AFrmPackage:=FlowPackages.Controls[i] as TFrmPackage;
      if (AFrmPackage.TaskID<>0) and (AFrmPackage.TaskID=LastEvent.I['data.id']) then
      begin
        CurrentTaskID:=LastEvent.I['data.id'];
        case LastEvent.S['event_type'] of
          'TASK_START':
          begin
            AFrmPackage.BtnCancel.Hide;
            AFrmPackage.ProgressBarInstall.Show;
            AFrmPackage.LabelProgressionInstall.Show;
            AFrmPackage.TextWaitInstall.Hide;
          end;
          'TASK_STATUS':
          begin
            AFrmPackage.ProgressBarInstall.Position:=LastEvent.I['data.progress'];
            AFrmPackage.LabelProgressionInstall.Caption:=IntToStr(LastEvent.I['data.progress'])+'%';
          end;
          'TASK_FINISH':
          begin
            AFrmPackage.ProgressBarInstall.Position:=LastEvent.I['data.progress'];
            AFrmPackage.ProgressBarInstall.Style:=pbstNormal;
            AFrmPackage.LabelProgressionInstall.Caption:=IntToStr(LastEvent.I['data.progress'])+'%';
            if (ShowOnlyInstalled or ShowOnlyNotInstalled or ShowOnlyUpgradable) then
              AFrmPackage.Autoremove:=true;
            LstTasks.Delete(LstTasks.IndexOf(UTF8Encode(AFrmPackage.Package.S['package'])));
            AFrmPackage.TaskID:=0;
            AFrmPackage.TimerInstallRemoveFinished.Enabled:=true;
            CurrentTaskID:=0;
          end;
          'TASK_ERROR':
          begin
            if (MessageDlg(Format(rsForce,[LastEvent.O['data'].S['description']]),mtWarning,mbYesNo,0)= mrYes) then
            begin
                LstTasks.Delete(LstTasks.IndexOf(UTF8Encode(AFrmPackage.Package.S['package'])));
                AFrmPackage.TaskID:=0;
                CurrentTaskID:=0;
                AFrmPackage.LaunchActionPackage(AFrmPackage.ActionPackage,AFrmPackage.Package,true)
            end
            else
            begin
              if (AFrmPackage.ActionPackage='install') then
              begin
                AFrmPackage.BtnInstallUpgrade.Caption:='Install';
                AFrmPackage.BtnInstallUpgrade.NormalColor:=clGreen;
                AFrmPackage.BtnInstallUpgrade.Enabled:=true;
                AFrmPackage.ActionPackage:='install';
              end
              else
              begin
                AFrmPackage.BtnRemove.NormalColor:=$005754E0;
                AFrmPackage.BtnRemove.Enabled:=true;
                AFrmPackage.ActionPackage:='remove';
                AFrmPackage.BtnInstallUpgrade.Caption:=rsStatusInstalled;
              end;
              AFrmPackage.ProgressBarInstall.Position:=0;
              AFrmPackage.ProgressBarInstall.Hide;
              AFrmPackage.LabelProgressionInstall.Caption:='0%';
              AFrmPackage.LabelProgressionInstall.Hide;
              AFrmPackage.TextWaitInstall.Hide;
              AFrmPackage.BtnCancel.Hide;
              LstTasks.Delete(LstTasks.IndexOf(UTF8Encode(AFrmPackage.Package.S['package'])));
              AFrmPackage.TaskID:=0;
            end;
          end;
        end;
        Exit();
      end;
    end;
  end;
end;

procedure TVisWaptSelf.OnCheckEventsThreadNotify(Sender: TObject);
var
  LastEvent,Events:ISuperObject;
begin
  try
    Events := (Sender as TCheckEventsThread).Events;
    if Events <> Nil then
    begin
      if (Events.AsArray<>Nil) and (Events.AsArray.Length>0) then
      for LastEvent in Events do
      begin
        case LastEvent.S['event_type'] of
          'PRINT': StaticText2.Caption:=UTF8Encode(lastEvent.S['data']);
          'TASK_START','TASK_STATUS','TASK_FINISH','TASK_ERROR':
          begin
            ProgressBarTaskRunning.Style:=pbstMarquee;
            ChangeProgressionFrmPackageOnEvent(LastEvent);
            StaticText1.Caption:= UTF8Encode(lastEvent.S['data.runstatus']);  //UTF8Encode(running.S['description']+': '+
            ProgressBarTaskRunning.Position:=Lastevent.I['data.progress'];
            if LastEvent.S['event_type']='TASK_FINISH' then
            begin
              if (LastEvent.S['data.classname']='WaptUpdate') then
              begin
                ActUpdatePackagesList.Execute;
                DownloadAllPackageIcons();
                FThreadGetAllIcons.Terminate;
                FThreadGetAllIcons:=TThreadGetAllIcons.Create(@OnUpgradeAllIcons,AllPackages,FlowPackages);
                FThreadGetAllIcons.FreeOnTerminate:=true;
              end
              else
                TTriggerWaptserviceAction.Create('packages.json?latest=1',@OnUpgradeTriggeredAllPackages,DMWaptSelf.Login,DMWaptSelf.Token,Nil);
              ProgressBarTaskRunning.Style:=pbstNormal;
            end;
          end;
          'STATUS':
          begin
          end;
        end;
      end;
    end
    else
    begin
       //service has been stopped
      if WAPTServiceRunning and not (Sender as TCheckEventsThread).WaptServiceRunning then
      begin
        WAPTServiceRunning:=False;
        CheckEventsThread.Terminate;
        CheckTasksThread.Terminate;
        Close;
      end;
    end
  except
  end
end;

function TVisWaptSelf.SelectedAreOnlyPending:Boolean;
var
  Task: ISuperObject;
begin
  Result:=True;
  for Task in SOGridTasks.SelectedRows do
    If Task.S['install_status'] <> 'PENDING' then
      Exit(False);
end;

procedure TVisWaptSelf.ChangeIconMinusByPlusOnFrames();
var
  i : integer;
  AFrmPackage : TFrmPackage;
begin
  for i:=0 to FlowPackages.ControlCount-1 do
  begin
    if (FlowPackages.Controls[i] is TFrmPackage) then
    begin
      AFrmPackage:=FlowPackages.Controls[i] as TFrmPackage;
      if (AFrmPackage.DetailsClicked) then
      begin
        AFrmPackage.DetailsClicked:=not(AFrmPackage.DetailsClicked);
        AFrmPackage.ImageDetails.Picture.LoadFromResourceName(HINSTANCE,'PLUS-BLEU-FONCE');
        break;
      end;
    end;
  end;
end;

function TVisWaptSelf.GetAllPackages: ISuperObject;
begin
  if FAllPackages = Nil then
    FAllPackages := DMWaptSelf.JSONGet('packages.json?latest=1');
  Result:=GetAllPackagesSorted(FAllPackages);
end;

procedure TVisWaptSelf.DownloadAllPackageIcons;
begin
  DMWaptSelf.JSONGet('download_icons?latest=1');
end;

procedure TVisWaptSelf.OnUpgradeTriggeredAllPackages(Sender: TObject);
begin
  FAllPackages:=(Sender as TTriggerWaptserviceAction).Res;
  if Assigned(FAllPackages) then
  begin
    FAllPackages:=GetAllPackagesSorted(FAllPackages);
  end;
end;


function TVisWaptSelf.IsValidFilter(package: ISuperObject): Boolean;
begin
  Result:=((ShowOnlyInstalled and (package.S['install_status'] = 'OK')) or (ShowOnlyNotInstalled and not(package.S['install_status'] = 'OK')) or (ShowOnlyUpgradable and (package.S['install_status'] = 'OK') and not(package.S['install_version'] = package.S['version'])) or (ShowOnlyNotInstalled=ShowOnlyUpgradable=ShowOnlyInstalled=false))
end;

function TVisWaptSelf.IsValidCategory(package: ISuperObject): Boolean;
begin
  Result:=(ComboBoxCategories.ItemIndex = ComboBoxCategories.Items.IndexOf(rsAllCategories)) or (pos(ComboBoxCategories.Items.Strings[ComboBoxCategories.ItemIndex],UTF8Encode(package.S['categories']))>0);
end;

function TVisWaptSelf.RemoveAccent(const AText : String):string;
const
  Char_Accents      = 'ÀÁÂÃÄÅàáâãäåÒÓÔÕÖØòóôõöøÈÉÊËèéêëÇçÌÍÎÏìíîïÙÚÛÜùúûüÿÑñ';
  Char_Sans_Accents = 'AAAAAAaaaaaaOOOOOOooooooEEEEeeeeCcIIIIiiiiUUUUuuuuyNn';
var
  i : integer;
  tmpstr : String;
begin
  for i:=1 to Length(Char_Accents) do
    tmpstr:=StringReplace(AText,Char_Accents[i],Char_Sans_Accents[i],[rfReplaceAll]);
  Result:=tmpstr
end;

function TVisWaptSelf.GetAllPackagesSorted(Pck: ISuperObject
  ): ISuperObject;
var
  Package : ISuperObject;
  tmp : String;
begin
  for Package in Pck do
  begin
    if pos('T',Package.S['signature_date'])<>0 then
    begin
       tmp:=UTF8Encode(Package.S['signature_date']);
       tmp:=copy(tmp,1,19);
       tmp:=ReplaceStr(tmp,'-','');
       tmp:=ReplaceStr(tmp,':','');
       tmp:=ReplaceStr(tmp,'T','-');
       Package.S['signature_date']:=UTF8Decode(tmp);
    end;
    if (UTF8Encode(Package.S['section'])='base') then
    begin
      if (UTF8Encode(Package.S['name'])='') then
      begin
        tmp:=UTF8Encode(Package.S['package']);
        tmp:=Copy(tmp,pos('-',tmp)+1,tmp.Length);
        tmp[1]:=upCase(tmp[1]);
        Package.S['name']:=UTF8Decode(tmp)
      end;
    end
    else
      Package.S['name']:=Package.S['package'];
    Package.S['namelower']:=LowerCase(Package.S['name']);
    Package.S['namelower']:=UTF8Decode(RemoveAccent(UTF8Encode(Package.S['namelower'])));
    if (GetDefaultLang='fr') and (Package.S['categories']<>'') then
    begin
      tmp:=UTF8Encode(Package.S['categories']);
      tmp:=ReplaceStr(tmp,'Utilities','Utilitaires');
      tmp:=ReplaceStr(tmp,'Messaging','Messagerie');
      tmp:=ReplaceStr(tmp,'Security','Sécurité');
      tmp:=ReplaceStr(tmp,'System and network','Système et sécurité');
      tmp:=ReplaceStr(tmp,'Media','Médias');
      tmp:=ReplaceStr(tmp,'Development','Développement');
      tmp:=ReplaceStr(tmp,'Office','Bureautique');
      tmp:=ReplaceStr(tmp,'Drivers','Pilotes');
      Package.S['categories']:=UTF8Decode(tmp);
    end;
  end;
  if (SortByName) then
    SortByFields(Pck,['namelower'],not(SortByNameAZ))
  else
    SortByFields(Pck,['signature_date'],not(SortByDateAsc));
  Result:=Pck;
end;

function TVisWaptSelf.GetAllCategories(Pck: ISuperObject): TStringList;
var
  LstCategories: TStringList;
  Package : ISuperObject;
begin
  LstCategories:=TStringList.Create;
  LstCategories.Sorted:=true;
  LstCategories.Duplicates:=dupIgnore;
  LstCategories.Delimiter:=',';
  LstCategories.StrictDelimiter:=true;
  LstCategories.DelimitedText:=rsAllCategories;
  for Package in Pck do
    if (UTF8Encode(Package.S['categories'])<>'') then
      LstCategories.DelimitedText:=LstCategories.DelimitedText+','+UTF8Encode(Package.S['categories']);
  Result:=LstCategories;
end;

function TVisWaptSelf.GoodSizeForScreen(ASize: integer): integer;
begin
  Result:=trunc((ASize*Screen.PixelsPerInch)/96);
end;

procedure TVisWaptSelf.EventsScrollBar(var TheMessage: TLMessage);
begin
  PrevWndProc(TheMessage);
  if (TheMessage.msg=LM_VSCROLL) then
  begin
  end;
end;

procedure TVisWaptSelf.AddFrameOnFlowPackages(Pck: ISuperObject);
var
  AFrmPackage : TFrmPackage;
  strtmp : String;
  IconIdx : Integer;
begin
  AFrmPackage:=TFrmPackage.Create(FlowPackages);
  AFrmPackage.Package:=Pck;
  with AFrmPackage do
  begin
      Parent := FlowPackages;
      Name := 'package' + IntToStr(LastNumberOfFrame);
      LabPackageName.Caption := UTF8Encode(package.S['name']);
      AdjustFont(LabPackageName);
      AdjustFont(LabVersion);
      strtmp := UTF8Encode(package.S['description']);
      if (strtmp.Length>125) then
      begin
        strtmp := copy(strtmp,1,125);
        strtmp := strtmp + '...';
      end;
      LabDescription.Caption := strtmp;

      strtmp := UTF8Encode(package.S['signature_date']);
      LabDate.Caption := Copy(strtmp,7,2)+'/'+Copy(strtmp,5,2)+'/'+Copy(strtmp,1,4);


      if (LstIcons <> Nil) then
      begin
        IconIdx := LstIcons.IndexOf(UTF8Encode(package.S['package_uuid'] + '.png'));
        if IconIdx>=0 then
          try
            ImgPackage.Picture.Assign(LstIcons.Objects[IconIdx] as TPicture);
          finally

          end;
      end;

      if (package.S['install_status'] = 'OK') then //Package installed
      begin
        LabVersion.Caption:=UTF8Encode(package.S['install_version']);
        if (package.S['install_version'] >= package.S['version']) then //Package installed and updated
          begin
            BtnInstallUpgrade.Caption:=rsStatusInstalled;
            BtnInstallUpgrade.Enabled:=false;
            BtnRemove.NormalColor:=$005754E0;
          end
        else                       //Package installed but not updated
          begin
            BtnInstallUpgrade.Caption:=rsActionUpgrade;
            BtnInstallUpgrade.NormalColor:=$004080FF;
            BtnRemove.NormalColor:=$005754E0;
            ActionPackage:='install';
            LabVersion.Caption:=UTF8Encode(package.S['version']);
          end;
      end
      else         //Package not installed
        begin
          ActionPackage:='install';
          BtnInstallUpgrade.NormalColor:=clGreen;
          BtnRemove.Enabled:=false;
          LabVersion.Caption:=UTF8Encode(package.S['version']);
        end;

      //PanelDetails

      FrmDetailsPackageInPanel:=Self.FrmDetailsPackageInPanel;
      PanelDetails:=Self.DetailsBarPanel;

      LstTasks:=Self.LstTasks;
      if (LstTasks.IndexOf(UTF8Encode(Package.S['package'])))<>-1 then
      begin
        {$IFDEF WINDOWS}
        TaskID:=Integer(LstTasks.Objects[LstTasks.IndexOf(UTF8Encode(Package.S['package']))]);
        {$ELSE}
        TaskID:=Integer(PtrUint(LstTasks.Objects[LstTasks.IndexOf(UTF8Encode(Package.S['package']))]));
        {$ENDIF}

        if (ActionPackage='install') then
          begin
            BtnInstallUpgrade.Enabled:=false;
            BtnInstallUpgrade.NormalColor:=$00C4C4C4;
            TextWaitInstall.Caption:=rsWaitingInstall;
            ActionPackage:='install';
          end
        else
          begin
            ActionPackage:='remove';
            BtnRemove.Enabled:=false;
            BtnRemove.NormalColor:=$00C4C4C4;
            TextWaitInstall.Caption:=rsWaitingRemove;
            TextWaitInstall.Show;
          end;
        TextWaitInstall.Show;
        BtnCancel.Show;
        if (TaskID=CurrentTaskID) then
        begin
          BtnCancel.Hide;
          ProgressBarInstall.Show;
          LabelProgressionInstall.Show;
          TextWaitInstall.Hide;
        end;
      end;

      if (Screen.PixelsPerInch<>96) then
      begin
        LabPackageName.FontEx.Height:=GoodSizeForScreen(LabPackageName.FontEx.Height);
        LabVersion.FontEx.Height:=GoodSizeForScreen(LabVersion.FontEx.Height);
        LabDescription.FontEx.Height:=GoodSizeForScreen(LabDescription.FontEx.Height);
        LabDate.FontEx.Height:=GoodSizeForScreen(LabDate.FontEx.Height);
        LabelProgressionInstall.FontEx.Height:=GoodSizeForScreen(LabelProgressionInstall.FontEx.Height);
        BtnInstallUpgrade.TextSize:=GoodSizeForScreen(BtnInstallUpgrade.TextSize);
        BtnCancel.TextSize:=GoodSizeForScreen(BtnCancel.TextSize);
        BtnRemove.TextSize:=GoodSizeForScreen(BtnRemove.TextSize);
        TextWaitInstall.FontEx.Height:=GoodSizeForScreen(TextWaitInstall.FontEx.Height);
        ImgPackage.AntialiasingMode:=amOn;
      end;
  end;
end;

function TVisWaptSelf.IsValidPackage(package: ISuperObject): Boolean;
var
  i:integer;
  keywordlst : TStringList;
begin
  keywordlst:=TStringList.Create;
  keywordlst.Duplicates:=dupIgnore;
  keywordlst.DelimitedText:=lowercase(EdSearch.Text);
  Result:=true;
  for i:=0 to keywordlst.Count-1 do
  begin
    if not((pos(keywordlst.Strings[i],lowercase(UTF8Encode(Package.S['name'])))>0) or (pos(keywordlst.Strings[i],lowercase(UTF8Encode(Package.S['description'])))>0) or (pos(keywordlst.Strings[i],lowercase(UTF8Encode(Package.S['editor'])))>0) or (pos(keywordlst.Strings[i],lowercase(UTF8Encode(Package.S['package'])))>0) or (pos(keywordlst.Strings[i],lowercase(UTF8Encode(Package.S['keywords'])))>0)) then
    begin
      FreeAndNil(keywordlst);
      Exit(false);
    end;
  end;
  FreeAndNil(keywordlst);
end;

{ TThreadGetAllIcons }

procedure TThreadGetAllIcons.NotifyListener;
begin
  If Assigned(FOnNotifyEvent) then
    FOnNotifyEvent(Self);
end;

procedure TThreadGetAllIcons.SetOnNotifyEvent(AValue: TNotifyEvent);
begin
  if FOnNotifyEvent=AValue then Exit;
  FOnNotifyEvent:=AValue;
end;

constructor TThreadGetAllIcons.Create(aNotifyEvent:TNotifyEvent;AllPackages:ISuperObject;aFlowPanel:TFlowPanel);
begin
  inherited Create(False);
  OnNotifyEvent:=aNotifyEvent;
  ListPackages:=AllPackages;
  FlowPanel:=aFlowPanel;
  FreeOnTerminate:=True;
end;

procedure TThreadGetAllIcons.Execute;
var
  IconsDir: String;
  Package: ISuperObject;
  i,IconIdx: integer;
  AFrmPackage: TFrmPackage;
  g:TPicture;
  iconPath: String;
begin
  IconsDir := GetIconsDir();

  try
    if not(DirectoryExists(IconsDir)) then
      CreateDir(IconsDir);

    for Package in ListPackages do
    begin
      tmpLstIcons := TStringList.Create;
      tmpLstIcons.OwnsObjects := True;

      try
        iconPath := IconsDir + UTF8Encode(Package.S['package_uuid'])+'.png';
        tmpLstIcons.Add(iconPath);
        g := TPicture.Create;
        g.LoadFromFile(tmpLstIcons[tmpLstIcons.IndexOf(iconPath)]);

        tmpLstIcons.Objects[tmpLstIcons.IndexOf(iconPath)] := g;
        tmpLstIcons[tmpLstIcons.IndexOf(iconPath)] := ExtractFileName(tmpLstIcons[tmpLstIcons.IndexOf(iconPath)]);
      except
        FreeAndNil(g);
        tmpLstIcons.Delete(tmpLstIcons.IndexOf(iconPath));
      end;

      for i:=0 to FlowPanel.ControlCount - 1 do
      begin
        try
          if not (FlowPanel.Controls[i] is TFrmPackage) then
             continue;

          AFrmPackage := FlowPanel.Controls[i] as TFrmPackage;
          if not (UTF8Encode(AFrmPackage.Package.S['package_uuid']) = UTF8Encode(Package.S['package_uuid'])) then
             continue;

          IconIdx := tmpLstIcons.IndexOf(UTF8Encode(AFrmPackage.Package.S['package_uuid'])+'.png');
          if IconIdx >= 0 then
          begin
            try
              AFrmPackage.ImgPackage.Picture.Assign(tmpLstIcons.Objects[IconIdx] as TPicture);
            except
            end;
            break;
          end;
        except
         On EListError do
            break;
        end;
      end;
      Synchronize(@NotifyListener);
    end;

  finally
  end;
end;

procedure TVisWaptSelf.OnUpgradeAllIcons(Sender: TObject);
var
  i: Integer;
  events: ISuperObject;
begin
  LstIcons.AddStrings((Sender as TThreadGetAllIcons).tmpLstIcons);

  // Fetching the last icon that was downloaded   
  events := CheckEventsThread.Events;
  if (Events = Nil) or (Events.AsArray.Length <= 0) then
     exit;
  for i := Events.AsArray.Length - 1 to 0 do
  begin
    try
      (Sender as TThreadGetAllIcons).lastIconDownloaded := CheckEventsThread.Events.AsArray[i]['data']['last_downloaded'].AsString();
      Exit;
    except
     Continue;
    end;
  end;
end;

end.

