unit uVisWaptSelf;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  EditBtn, StdCtrls, Buttons, CheckLst, ActnList, uvislogin, BCListBox,
  BCMaterialDesignButton, BCLabel, IdAuthentication, superobject,
  waptcommon, httpsend, sogrid, uWAPTPollThreads, VirtualTrees, ImgList,
  ComCtrls;

type

  { TVisWaptSelf }

  TVisWaptSelf = class(TForm)
    ActCancelTask: TAction;
    ActUpdatePackagesList: TAction;
    ActTriggerSearch: TAction;
    ActUnselectAllKeywords: TAction;
    ActSearchPackages: TAction;
    ActionList1: TActionList;
    BCLabel1: TBCLabel;
    BtnCancelTasks: TBitBtn;
    BtnUpdateList: TButton;
    BtnShowInstalled: TButton;
    BtnShowNotInstalled: TButton;
    BtnShowUpgradable: TButton;
    BtnShowAll: TButton;
    BtnUnselectAllKeywords: TButton;
    CBKeywords: TCheckListBox;
    EdSearch: TEditButton;
    FlowPackages: TFlowPanel;
    ImageListTaskStatus: TImageList;
    ImageLogo: TImage;
    Panel1: TPanel;
    PanCategories: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
    Panel7: TPanel;
    ProgressBarTaskRunning: TProgressBar;
    ScrollBoxPackages: TScrollBox;
    SOGridTasks: TSOGrid;
    Splitter1: TSplitter;
    StaticText1: TStaticText;
    StaticText2: TStaticText;
    TimerSearch: TTimer;
    procedure ActCancelTaskExecute(Sender: TObject);
    procedure ActCancelTaskUpdate(Sender: TObject);
    procedure ActSearchPackagesExecute(Sender: TObject);
    procedure ActShowAllClearFilters(Sender: TObject);
    procedure ActShowInstalled(Sender: TObject);
    procedure ActShowNotInstalled(Sender: TObject);
    procedure ActShowUpgradable(Sender: TObject);
    procedure ActTriggerSearchExecute(Sender: TObject);
    procedure ActUnselectAllKeywordsExecute(Sender: TObject);
    procedure ActUpdatePackagesListExecute(Sender: TObject);
    procedure EdSearchButtonClick(Sender: TObject);
    procedure EdSearchChange(Sender: TObject);
    procedure EdSearchKeyPress(Sender: TObject; var Key: char);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure SOGridTasksGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: Integer;
      var ImageList: TCustomImageList);
    procedure TimerSearchTimer(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormClose(Sender: TObject);
  private
    function GetAllPackages: ISuperObject;
  private
    ShowOnlyUpgradable: Boolean;
    ShowOnlyInstalled: Boolean;
    ShowOnlyNotInstalled: Boolean;
    SortByDate:Boolean;
    WAPTServiceRunning:Boolean;
    LastTaskIDOnLaunch:integer;

    LstIcons: TStringList;
    FAllPackages: ISuperObject;

    login: String;
    password: String;

    procedure OnLocalServiceAuth(Sender: THttpSend; var ShouldRetry: Boolean;RetryCount:integer);
    function IsValidPackage(package : ISuperObject):Boolean;
    function IsValidKeyword(package : ISuperObject):Boolean;
    function IsValidFilter(package : ISuperObject):Boolean;

    procedure OnCheckTasksThreadNotify(Sender: TObject);
    procedure ChangeProgressionFrmPackageOnEvent(LastEvent: ISuperObject);
    function SelectedAreOnlyPending: Boolean;
    procedure OnCheckEventsThreadNotify(Sender: TObject);
    procedure UpdatePackage(NamePackage:String);
    property AllPackages:ISuperObject read GetAllPackages write FAllPackages;
  public
    CheckTasksThread: TCheckAllTasksThread;
    CheckEventsThread: TCheckEventsThread;
  end;

var
  VisWaptSelf: TVisWaptSelf;

implementation
uses uFrmPackage,LCLIntf, LCLType,waptwinutils;
{$R *.lfm}

{ TVisWaptSelf }

procedure TVisWaptSelf.EdSearchButtonClick(Sender: TObject);
begin
  ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.ActSearchPackagesExecute(Sender: TObject);
var
  package:ISuperObject;
  AFrmPackage:TFrmPackage;
  idx,IconIdx,maxidx:Integer;
  begin
  try
    TimerSearch.Enabled:=False;
    Screen.Cursor:=crHourGlass;
    FlowPackages.DisableAlign;

    for idx := FlowPackages.ControlCount-1 downto 0 do
      FlowPackages.Controls[idx].Free;
    FlowPackages.ControlList.Clear;

    idx:=1;
    maxidx:=((maxSmallint div 188) div 3);

    for package in AllPackages do
    begin
      if IsValidPackage(package) and IsValidKeyword(package) and IsValidFilter(package) then
      begin
          AFrmPackage := TFrmPackage.Create(FlowPackages);
          AFrmPackage.Parent := FlowPackages;
          AFrmPackage.Name:='package'+IntToStr(idx);
          AFrmPackage.LabPackageName.Caption:=UTF8Encode(package.S['package']);
          AFrmPackage.AdjustFont(AFrmPackage.LabPackageName);
          AFrmPackage.LabVersion.Caption:=UTF8Encode(package.S['version']);
          AFrmPackage.AdjustFont(AFrmPackage.LabVersion);
          AFrmPackage.LabDescription.Caption:=UTF8Encode(package.S['description']);
          AFrmPackage.LabMaintainer.Caption:='by '+UTF8Encode(package.S['maintainer']);
          AFrmPackage.AdjustFont(AFrmPackage.LabMaintainer);
          AFrmPackage.Package:=package;

          IconIdx := LstIcons.IndexOf(UTF8Encode(package.S['package']+'.png'));
          if IconIdx<0 then
            IconIdx:=LstIcons.IndexOf('unknown.png');

          if IconIdx>=0 then
            AFrmPackage.ImgPackage.Picture.Assign(LstIcons.Objects[IconIdx] as TPicture);

          if (package.S['install_status'] = 'OK') then //Package installed
          begin
            if (package.S['install_version'] = package.S['version']) then //Package installed and updated
              with AFrmPackage do
              begin
                BtnInstallUpgrade.Caption:='Installed';
                BtnInstallUpgrade.Enabled:=false;
                BtnRemove.NormalColor:=clRed;
              end
            else                       //Package installed but not updated
              with AFrmPackage do
              begin
                BtnInstallUpgrade.Caption:='Upgrade';
                BtnInstallUpgrade.NormalColor:=$004080FF;
                LabInstallVersion.Caption:='(over '+UTF8Encode(package.S['install_version'])+')';
                AdjustFont(AFrmPackage.LabInstallVersion);
                LabInstallVersion.Visible:=True;
                BtnRemove.NormalColor:=clRed;
                ActionPackage:='install';
              end;
          end
          else         //Package not installed
            with AFrmPackage do
            begin
              ActionPackage:='install';
              BtnInstallUpgrade.NormalColor:=clGreen;
              BtnRemove.Enabled:=false;
            end;

          //Identification
          AFrmPackage.login:=login;
          AFrmPackage.password:=password;
          AFrmPackage.OnLocalServiceAuth:=@OnLocalServiceAuth;

          inc(idx);
          if idx>maxidx then
            break;
        end;
      end;
  finally
    FlowPackages.EnableAlign;
    Screen.Cursor:=crDefault;
  end;
end;

function TVisWaptSelf.SelectedAreOnlyPending:Boolean;
var
  task: ISuperObject;
begin
  Result:=True;
  for task in SOGridTasks.SelectedRows do
    If task.S['install_status'] <> 'PENDING' then
      Exit(False);
end;

procedure TVisWaptSelf.ActCancelTaskUpdate(Sender: TObject);
begin
  ActCancelTask.Enabled := (SOGridTasks.SelectedCount>0 ) and (SelectedAreOnlyPending);
end;

procedure TVisWaptSelf.ActCancelTaskExecute(Sender: TObject);
var
 Task : ISuperObject;
begin
  for Task in SOGridTasks.SelectedRows do
    WAPTLocalJsonGet(Format('cancel_task.json?id=%d',[Task.I['id']]),login,password,-1,@OnLocalServiceAuth,2);
end;

procedure TVisWaptSelf.ActShowAllClearFilters(Sender: TObject);
begin
  ShowOnlyNotInstalled:=false;
  ShowOnlyUpgradable:=false;
  ShowOnlyInstalled:=false;
  SortByDate:=false;
  CBKeywords.CheckAll(cbUnchecked);
  EdSearch.Text:='';
  ActSearchPackages.Execute;
  BtnShowInstalled.Enabled:=true;
  BtnShowAll.Enabled:=false;
  BtnShowNotInstalled.Enabled:=true;
  BtnShowUpgradable.Enabled:=true;
end;

procedure TVisWaptSelf.ActShowInstalled(Sender: TObject);
begin
   ShowOnlyNotInstalled:=false;
   ShowOnlyUpgradable:=false;
   ShowOnlyInstalled:=true;
   BtnShowInstalled.Enabled:=false;
   BtnShowAll.Enabled:=true;
   BtnShowNotInstalled.Enabled:=true;
   BtnShowUpgradable.Enabled:=true;
   ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.ActShowNotInstalled(Sender: TObject);
begin
   ShowOnlyNotInstalled:=true;
   ShowOnlyUpgradable:=false;
   ShowOnlyInstalled:=false;
   ActSearchPackages.Execute;
   BtnShowInstalled.Enabled:=true;
   BtnShowAll.Enabled:=true;
   BtnShowNotInstalled.Enabled:=false;
   BtnShowUpgradable.Enabled:=true;
end;

procedure TVisWaptSelf.ActShowUpgradable(Sender: TObject);
begin
  ShowOnlyNotInstalled:=false;
  ShowOnlyUpgradable:=true;
  ShowOnlyInstalled:=false;
  ActSearchPackages.Execute;
  BtnShowInstalled.Enabled:=true;
   BtnShowAll.Enabled:=true;
   BtnShowNotInstalled.Enabled:=true;
   BtnShowUpgradable.Enabled:=false;
end;

procedure TVisWaptSelf.ActTriggerSearchExecute(Sender: TObject);
begin
  TimerSearch.Enabled:=False;
  TimerSearch.Enabled:=True;
end;

procedure TVisWaptSelf.ActUnselectAllKeywordsExecute(Sender: TObject);
begin
  CBKeywords.CheckAll(cbUnchecked);
  ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.ActUpdatePackagesListExecute(Sender: TObject);
begin
  FAllPackages:=Nil;
  ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.EdSearchChange(Sender: TObject);
begin
  TimerSearch.Enabled:=False;
  TimerSearch.Enabled:=True;
end;

procedure TVisWaptSelf.EdSearchKeyPress(Sender: TObject; var Key: char);
begin
  if Key = #13 then
  begin
    EdSearch.SelectAll;
    ActSearchPackages.Execute;
  end;
end;

procedure TVisWaptSelf.FormCreate(Sender: TObject);
var
  i:integer;
  g:TPicture;
begin
  ReadWaptConfig();
  //TODO : relative path
  //TODO : get icons pack from server on demand
  ShowOnlyInstalled:=false;
  ShowOnlyNotInstalled:=false;
  ShowOnlyUpgradable:=false;
  SortByDate:=false;

  //TODO : remove login/password

  login:=waptwinutils.AGetUserName;
  password:='';


  LstIcons := FindAllFiles(WaptBaseDir+'\cache\icons','*.png',False);
  LstIcons.OwnsObjects:=True;
  for i := 0 to LstIcons.Count-1 do
    try
      g := TPicture.Create;
      g.LoadFromFile(LstIcons[i]);
      LstIcons.Objects[i] := g;
      LstIcons[i] := ExtractFileName(LstIcons[i]);
    except
    end;
end;

procedure TVisWaptSelf.FormShow(Sender: TObject);
var
  keyword,keywords: ISuperObject;
begin
  try
    Screen.Cursor := crHourGlass;
    keywords:=WAPTLocalJsonGet('keywords.json?latest=1',login,password,-1,@OnLocalServiceAuth,2);
    CBKeywords.Clear;
    for keyword in keywords do
      CBKeywords.Items.Add(UTF8Encode(keyword.AsString));

    // Check running / pending tasks
    CheckTasksThread := TCheckAllTasksThread.Create(@OnCheckTasksThreadNotify);
    CheckEventsThread := TCheckEventsThread.Create(@OnCheckEventsThreadNotify);
    CheckTasksThread.Start;
    CheckEventsThread.Start;
    LastTaskIDOnLaunch:=-1;

    TimerSearch.Enabled:=False;
    TimerSearch.Enabled:=True;

  finally
    Screen.Cursor := crDefault;
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

procedure TVisWaptSelf.FormDestroy(Sender: TObject);
begin
  FreeAndNil(CheckTasksThread);
  FreeAndNil(CheckEventsThread);
  LstIcons.free;
end;

procedure TVisWaptSelf.FormClose(Sender: TObject);
begin
  CheckTasksThread.Terminate;
  CheckEventsThread.Terminate;
end;

function TVisWaptSelf.GetAllPackages: ISuperObject;
begin
  if FAllPackages = Nil then
    FAllPackages := WAPTLocalJsonGet('packages.json?latest=1',login,password,-1,@OnLocalServiceAuth,2);
  Result := FAllPackages;
end;

procedure TVisWaptSelf.OnLocalServiceAuth(Sender: THttpSend; var ShouldRetry: Boolean;RetryCount:integer);
var
  LoginDlg: TVisLogin;
begin
  LoginDlg := TVisLogin.Create(Self);
  try
    if LoginDlg.ShowModal=mrOk then
    begin
      Sender.UserName:= LoginDlg.EdUsername.text;
      Sender.Password:= LoginDlg.EdPassword.text;
      login:= LoginDlg.EdUsername.text;
      password:= LoginDlg.EdPassword.text;
      ShouldRetry := (Sender.UserName<>'') and (Sender.Password<>'');
    end
  finally
    LoginDlg.Free;
  end;
end;

function TVisWaptSelf.IsValidPackage(package: ISuperObject): Boolean;
begin
  Result:=(pos(lowercase(EdSearch.Text),lowercase(Package.S['package']))>0) or (EdSearch.Text='');
end;

function TVisWaptSelf.IsValidKeyword(package: ISuperObject): Boolean;
var
  i:integer;
begin
  Result:=true;
  for i:=0 to CBKeywords.Items.Count-1 do
    if (CBKeywords.Checked[i]) and (pos(lowercase(CBKeywords.Items[i]),lowercase(package.S['keywords']))=0) then
      exit(false);
end;

function TVisWaptSelf.IsValidFilter(package: ISuperObject): Boolean;
begin
  Result:=((ShowOnlyInstalled and (package.S['install_status'] = 'OK')) or (ShowOnlyNotInstalled and not(package.S['install_status'] = 'OK')) or (ShowOnlyUpgradable and (package.S['install_status'] = 'OK') and not(package.S['install_version'] = package.S['version'])) or (ShowOnlyNotInstalled=ShowOnlyUpgradable=ShowOnlyInstalled=false))
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
    AFrmPackage:=FlowPackages.Controls[i] as TFrmPackage;
    if Assigned(AFrmPackage.Task) and (AFrmPackage.Task.I['id']=LastEvent.I['data.id']) then
    begin
      if (LastEvent.S['event_type']='TASK_START') then
      begin
        AFrmPackage.FXProgressBarInstall.Show;
        AFrmPackage.LabelProgressionInstall.Show;
        AFrmPackage.TextWaitInstall.Hide;
      end
      else if (LastEvent.S['event_type']='TASK_STATUS') then
        begin
          AFrmPackage.FXProgressBarInstall.Value:=LastEvent.I['data.progress'];
          AFrmPackage.LabelProgressionInstall.Caption:=IntToStr(LastEvent.I['data.progress'])+'%';
        end
        else
        begin
          AFrmPackage.FXProgressBarInstall.Value:=LastEvent.I['data.progress'];
          AFrmPackage.LabelProgressionInstall.Caption:=IntToStr(LastEvent.I['data.progress'])+'%';
          UpdatePackage(UTF8Encode(LastEvent.O['data'].O['packagenames'].S['0']));//UPDATE PACKAGE ISUPEROBJECT DELETE OLD ENTRY ADD NEW
          AFrmPackage.TimerInstallRemoveFinished.Enabled:=true;
        end;
    Exit();
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
          'TASK_START','TASK_STATUS','TASK_FINISH':
          begin
            //StaticText1.Caption:= UTF8Encode(running.S['description']+': '+lastEvent.S['data.runstatus']);
            ChangeProgressionFrmPackageOnEvent(LastEvent);
            StaticText1.Caption:= UTF8Encode(LastEvent.S['data.runstatus']);
            ProgressBarTaskRunning.Position:=Lastevent.I['data.progress'];
          end;
          'STATUS': //GridPendingUpgrades.Data := GetPackageStatus(lastEvent['data']);
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

procedure TVisWaptSelf.UpdatePackage(NamePackage: String);
var
  NewEntry: ISuperObject;
  i:integer;
begin
  try
    NewEntry:=WAPTLocalJsonGet(Format('local_package_details.json?package=%s',[NamePackage]),login,password,-1,@OnLocalServiceAuth,2);
    StaticText1.Caption:=IntToStr(AllPackages.AsArray.Length-1);
    for i:=0 to AllPackages.AsArray.Length-1 do
    begin
      if (UTF8Encode(AllPackages.AsArray[i].S['package'])=NamePackage) then
      begin
        AllPackages.AsArray[i]:=NewEntry.AsArray[0];
        Exit();
      end;
    end;
  finally
  end;
end;

end.

