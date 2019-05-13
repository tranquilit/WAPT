unit uVisWaptSelf;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  EditBtn, StdCtrls, Buttons, CheckLst, ActnList, uvislogin, BCListBox,
  BCMaterialDesignButton, BCLabel, IdAuthentication, superobject,
  waptcommon, httpsend, sogrid, uWAPTPollThreads, VirtualTrees, ImgList,
  ComCtrls, uFrmPackage;

type

  { TThreadGetAllIcons }
  TThreadGetAllIcons = class(TThread)
  private
    FOnNotifyEvent: TNotifyEvent;
    procedure NotifyListener; Virtual;
    procedure SetOnNotifyEvent(AValue: TNotifyEvent);
  public
    LstIcons : TStringList;
    ListPackages : ISuperObject;
    FlowPanel : TFlowPanel;
    property OnNotifyEvent:TNotifyEvent read FOnNotifyEvent write SetOnNotifyEvent;
    constructor Create(aNotifyEvent:TNotifyEvent;AllPackages:ISuperObject; aFlowPanel:TFlowPanel);
    procedure Execute; override;
  end;

  { TVisWaptSelf }

  TVisWaptSelf = class(TForm)
    ActCancelTask: TAction;
    ActShowTaskBar: TAction;
    ActUpdatePackagesList: TAction;
    ActTriggerSearch: TAction;
    ActUnselectAllKeywords: TAction;
    ActSearchPackages: TAction;
    ActionList1: TActionList;
    BtnCancelTasks: TBitBtn;
    BtnShowTaskBar: TButton;
    LabPackageList: TLabel;
    PicLogo: TImage;
    LabelNoResult: TLabel;
    BtnUpdateList: TButton;
    BtnShowInstalled: TButton;
    BtnShowNotInstalled: TButton;
    BtnShowUpgradable: TButton;
    BtnShowAll: TButton;
    BtnUnselectAllKeywords: TButton;
    BtnSortByDate: TButton;
    CBKeywords: TCheckListBox;
    EdSearch: TEditButton;
    FlowPackages: TFlowPanel;
    ImageListTaskStatus: TImageList;
    ImageLogo: TImage;
    Panel1: TPanel;
    PanCategories: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
    Panel4: TPanel;
    Panel5: TPanel;
    Panel6: TPanel;
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
    procedure ActShowTaskBarExecute(Sender: TObject);
    procedure ActShowUpgradable(Sender: TObject);
    procedure ActSortByDate(Sender: TObject);
    procedure ActTriggerSearchExecute(Sender: TObject);
    procedure ActUnselectAllKeywordsExecute(Sender: TObject);
    procedure ActUpdatePackagesListExecute(Sender: TObject);
    procedure EdSearchButtonClick(Sender: TObject);
    procedure EdSearchChange(Sender: TObject);
    procedure EdSearchKeyPress(Sender: TObject; var Key: char);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure ImageLogoClick(Sender: TObject);
    procedure SOGridTasksGetImageIndexEx(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: Integer;
      var ImageList: TCustomImageList);
    procedure TimerSearchTimer(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormClose(Sender: TObject);
  private
    ShowOnlyUpgradable: Boolean;
    ShowOnlyInstalled: Boolean;
    ShowOnlyNotInstalled: Boolean;
    SortByDateAsc:Boolean;
    ShowTaskBar: Boolean;
    WAPTServiceRunning:Boolean;
    LastTaskIDOnLaunch:integer;
    CurrentTaskID:integer;

    LstIcons: TStringList;
    LstTasks: TStringList;
    FAllPackages: ISuperObject;

    FThreadGetAllIcons: TThreadGetAllIcons;

    login: String;
    password: String;

    function GetAllPackages: ISuperObject;
    procedure OnUpgradeTriggeredAllPackages(Sender : TObject);

    procedure OnUpgradeAllIcons(Sender : TObject);

    //Authentification
    procedure OnLocalServiceAuth(Sender: THttpSend; var ShouldRetry: Boolean;RetryCount:integer);

    //Polling thread
    procedure OnCheckTasksThreadNotify(Sender: TObject);
    procedure OnCheckEventsThreadNotify(Sender: TObject);
    procedure ChangeProgressionFrmPackageOnEvent(LastEvent: ISuperObject);

    //Functions for generate frames
    function IsValidPackage(package : ISuperObject):Boolean;
    function IsValidKeyword(package : ISuperObject):Boolean;
    function IsValidFilter(package : ISuperObject):Boolean;
    function SelectedAreOnlyPending: Boolean;

    property AllPackages:ISuperObject read GetAllPackages write FAllPackages;

  public
    CheckTasksThread: TCheckAllTasksThread;
    CheckEventsThread: TCheckEventsThread;
  end;

var
  VisWaptSelf: TVisWaptSelf;


implementation
uses LCLIntf, LCLType, waptwinutils, soutils, strutils, uWaptSelfRes, openssl,fphttpclient, IniFiles;
{$R *.lfm}

{ TVisWaptSelf }

procedure TVisWaptSelf.ActSearchPackagesExecute(Sender: TObject);
var
  package:ISuperObject;
  AFrmPackage:TFrmPackage;
  idx,IconIdx,maxidx:Integer;
  strtmp:String;
  begin
  try
    TimerSearch.Enabled:=False;
    Screen.Cursor:=crHourGlass;
    FlowPackages.DisableAlign;

    for idx := FlowPackages.ControlCount-1 downto 0 do
      FlowPackages.Controls[idx].Free;
    FlowPackages.ControlList.Clear;

    idx:=1;
    maxidx:=((maxSmallint div 188) div 2);

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
          strtmp:=UTF8Encode(package.S['signature_date']);
          AFrmPackage.LabDate.Caption:=Copy(strtmp,7,2)+'/'+Copy(strtmp,5,2)+'/'+Copy(strtmp,1,4);

          if (LstIcons<>Nil) then
          begin
          IconIdx := LstIcons.IndexOf(UTF8Encode(package.S['package']+'.png'));
          if IconIdx>=0 then
            AFrmPackage.ImgPackage.Picture.Assign(LstIcons.Objects[IconIdx] as TPicture);
          end;

          if (package.S['install_status'] = 'OK') then //Package installed
          begin
            if (package.S['install_version'] = package.S['version']) then //Package installed and updated
              with AFrmPackage do
              begin
                BtnInstallUpgrade.Caption:=rsStatusInstalled;
                BtnInstallUpgrade.Enabled:=false;
                BtnRemove.NormalColor:=clRed;
              end
            else                       //Package installed but not updated
              with AFrmPackage do
              begin
                BtnInstallUpgrade.Caption:=rsActionUpgradable;
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

          AFrmPackage.LstTasks:=LstTasks;
          if (LstTasks.IndexOf(UTF8Encode(AFrmPackage.Package.S['package'])))<>-1 then
          begin
            AFrmPackage.TaskID:=Integer(LstTasks.Objects[LstTasks.IndexOf(UTF8Encode(AFrmPackage.Package.S['package']))]);
            with AFrmPackage do
            begin
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
              LabDescription.Hide;
              BtnCancel.Show;
              if (TaskID=CurrentTaskID) then
              begin
                BtnCancel.Hide;
                ProgressBarInstall.Show;
                LabelProgressionInstall.Show;
                TextWaitInstall.Hide;
              end;
            end;
          end;

          inc(idx);
          if idx>maxidx then
            break;
        end;
      end;

    if (idx=1) then
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

procedure TVisWaptSelf.ActCancelTaskUpdate(Sender: TObject);
begin
  ActCancelTask.Enabled := (SOGridTasks.SelectedCount>0 ) and (SelectedAreOnlyPending);
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
  SortByDateAsc:=false;
  CBKeywords.CheckAll(cbUnchecked);
  ActSearchPackages.Execute;
  BtnShowInstalled.Enabled:=true;
  BtnShowAll.Enabled:=false;
  BtnShowNotInstalled.Enabled:=true;
  BtnShowUpgradable.Enabled:=true;
  LabPackageList.Caption := rsAvailablePackages;
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
   LabPackageList.Caption := rsInstalledPackages;
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
   LabPackageList.Caption := rsNotInstalledPackages;
end;

procedure TVisWaptSelf.ActShowTaskBarExecute(Sender: TObject);
begin
  if ShowTaskBar then
  begin
    Panel3.Hide;
    BtnShowTaskBar.Caption:=rsShowTaskBar;
  end
  else
  begin
    Panel3.Show;
    BtnShowTaskBar.Caption:=rsHideTaskBar;
  end;
  ShowTaskBar:=not ShowTaskBar;
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
  LabPackageList.Caption := rsUpgradablePackages;
end;

procedure TVisWaptSelf.ActSortByDate(Sender: TObject);
begin
  if not(SortByDateAsc) then
    BtnSortByDate.Caption:=rsSortByDateAsc
  else
    BtnSortByDate.Caption:=rsSortByDateDesc;
  SortByDateAsc:=not(SortByDateAsc);
  ActSearchPackages.Execute;
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

procedure TVisWaptSelf.EdSearchButtonClick(Sender: TObject);
begin
  ActSearchPackages.Execute;
end;

procedure TVisWaptSelf.EdSearchKeyPress(Sender: TObject; var Key: char);
begin
  if Key = #13 then
  begin
    EdSearch.SelectAll;
    ActSearchPackages.Execute;
  end;
end;

procedure TVisWaptSelf.FormClose(Sender: TObject; var CloseAction: TCloseAction
  );
begin
  if Assigned(FThreadGetAllIcons) then
    FThreadGetAllIcons.Terminate;
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

procedure TVisWaptSelf.FormCreate(Sender: TObject);
var
  ini : TIniFile;
begin
  ReadWaptConfig();
  ShowOnlyInstalled:=false;
  ShowOnlyNotInstalled:=false;
  ShowOnlyUpgradable:=false;
  SortByDateAsc:=false;

  login:=waptwinutils.AGetUserName;
  password:='';

  LstTasks:=TStringList.Create;
  LstTasks.Sorted:=true;
  LstTasks.Duplicates:=dupIgnore;
  CurrentTaskID:=0;

  {$ifdef ENTERPRISE }
  if FileExists(WaptBaseDir+'\templates\waptself-logo.png') then
    PicLogo.Picture.LoadFromFile(WaptBaseDir+'\templates\waptself-logo.png')
  else
    PicLogo.Picture.LoadFromResourceName(HINSTANCE,'WAPT_ENTERPRISE');
  {$endif}

  //Create AppLocal/Waptself
  if not(DirectoryExists(AppLocalDir)) then
    CreateDir(AppLocalDir);
  //Create ini
  if not(FileExists(AppIniFilename)) then
  begin
    ini:=TIniFile.Create(AppIniFilename);
    ini.UpdateFile;
    FreeAndNil(ini);
  end;
end;

procedure TVisWaptSelf.FormDestroy(Sender: TObject);
begin
  FreeAndNil(CheckTasksThread);
  FreeAndNil(CheckEventsThread);
  FreeAndNil(LstIcons);
  FreeAndNil(LstTasks);
end;

procedure TVisWaptSelf.OnUpgradeAllIcons(Sender: TObject);
begin
  LstIcons:=(Sender as TThreadGetAllIcons).LstIcons;
end;

procedure TVisWaptSelf.FormShow(Sender: TObject);
var
  keyword,keywords: ISuperObject;
begin
  try
    MakeFullyVisible();
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
    ShowTaskBar:=false;
    GetAllPackages();
    FThreadGetAllIcons := TThreadGetAllIcons.Create(@OnUpgradeAllIcons,AllPackages,FlowPackages);
    TimerSearch.Enabled:=False;
    TimerSearch.Enabled:=True;
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TVisWaptSelf.ImageLogoClick(Sender: TObject);
begin
  OpenDocument('https://www.tranquil.it');
end;

procedure TVisWaptSelf.FormClose(Sender: TObject);
begin
  CheckTasksThread.Terminate;
  CheckEventsThread.Terminate;
end;

procedure TVisWaptSelf.OnLocalServiceAuth(Sender: THttpSend; var ShouldRetry: Boolean;RetryCount:integer);
var
  LoginDlg: TVisLogin;

begin
  LoginDlg:=TVisLogin.Create(Self);
  LoginDlg.EdUsername.text:=login;
  try
    if LoginDlg.ShowModal=mrOk then
    begin
      Sender.UserName:=LoginDlg.EdUsername.text;
      Sender.Password:=LoginDlg.EdPassword.text;
      login:=LoginDlg.EdUsername.text;
      password:=LoginDlg.EdPassword.text;
      ShouldRetry:=(Sender.UserName<>'') and (Sender.Password<>'');
    end
  finally
    LoginDlg.Free;
  end;
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
              AFrmPackage.BtnRemove.NormalColor:=clRed;
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
              TTriggerWaptserviceAction.Create('packages.json?latest=1',@OnUpgradeTriggeredAllPackages,login,password,@OnLocalServiceAuth);
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

function TVisWaptSelf.GetAllPackages: ISuperObject;
var
  Package: ISuperObject;
  tmp:String;
begin
  if FAllPackages = Nil then
    FAllPackages := WAPTLocalJsonGet('packages.json?latest=1',login,password,-1,@OnLocalServiceAuth,2);
  for Package in FAllPackages do
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
  end;
  SortByFields(FAllPackages,['signature_date'],not(SortByDateAsc));
  Result:=FAllPackages;
end;

procedure TVisWaptSelf.OnUpgradeTriggeredAllPackages(Sender: TObject);
var
  tmp: String;
  Package : ISuperObject;
begin
  FAllPackages:=(Sender as TTriggerWaptserviceAction).Res;
  if Assigned(FAllPackages) then
  begin
    for Package in FAllPackages do
        if pos('T',Package.S['signature_date'])<>0 then
        begin
           tmp:=UTF8Encode(Package.S['signature_date']);
           tmp:=copy(tmp,1,19);
           tmp:=ReplaceStr(tmp,'-','');
           tmp:=ReplaceStr(tmp,':','');
           tmp:=ReplaceStr(tmp,'T','-');
           Package.S['signature_date']:=UTF8Decode(tmp);
        end;
    SortByFields(FAllPackages,['signature_date'],not(SortByDateAsc));
  end;
end;

function TVisWaptSelf.IsValidFilter(package: ISuperObject): Boolean;
begin
  Result:=((ShowOnlyInstalled and (package.S['install_status'] = 'OK')) or (ShowOnlyNotInstalled and not(package.S['install_status'] = 'OK')) or (ShowOnlyUpgradable and (package.S['install_status'] = 'OK') and not(package.S['install_version'] = package.S['version'])) or (ShowOnlyNotInstalled=ShowOnlyUpgradable=ShowOnlyInstalled=false))
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
  LstIcons:=Nil;
  ListPackages:=AllPackages;
  FlowPanel:=aFlowPanel;
  FreeOnTerminate:=True;
end;

procedure TThreadGetAllIcons.Execute;
var
  IconsDir:String;
  Package : ISuperObject;
  FS: TStream;
  Client: TFPHTTPClient;
  i,IconIdx:integer;
  g:TPicture;
  ini:TIniFile;
  AFrmPackage: TFrmPackage;
begin
  IconsDir:=AppLocalDir+'\icons\';
  ini:=TIniFile.Create(AppIniFilename);
  if (ini.ReadString('global','LastPackageDate','None') = 'None') or (ini.ReadString('global','LastPackageDate','None') = '') or (ini.ReadString('global','LastPackageDate','None') < (UTF8Encode(ListPackages.O['0'].S['signature_date']))) then
  begin
    if not(DirectoryExists(IconsDir)) then
      CreateDir(IconsDir);
    InitSSLInterface;
    Client:=TFPHttpClient.Create(nil);
    Client.AllowRedirect := true;
    for Package in ListPackages do
    begin
      if Terminated then
        Exit;
      if (((UTF8Encode(Package.S['signature_date']))<=(ini.ReadString('global','LastPackageDate','None'))) and not((ini.ReadString('global','LastPackageDate','None') = 'None'))) then
        break;
      if FileExists(IconsDir+UTF8Encode(Package.S['package'])+'.png') then
        DeleteFile(IconsDir+UTF8Encode(Package.S['package'])+'.png');
      FS:=TFileStream.Create(IconsDir+UTF8Encode(Package.S['package'])+'.png',fmCreate or fmOpenWrite);
      try
        Client.Get(UTF8Encode(Package.S['repo_url'])+'/icons/'+UTF8Encode(Package.S['package'])+'.png',FS);
      except
        On EHTTPClient do
        begin
          FreeAndNil(FS);
          DeleteFile(IconsDir+UTF8Encode(Package.S['package'])+'.png');
        end;
      end;
      FreeAndNil(FS);
    end;
    FreeAndNil(Client);

    ini.WriteString('global','LastPackageDate',UTF8Encode(ListPackages.O['0'].S['signature_date']));
    ini.UpdateFile;
  end;
  FreeAndNil(ini);

  LstIcons:=FindAllFiles(IconsDir,'*.png',False);
  LstIcons.OwnsObjects:=True;
  for i:=0 to LstIcons.Count-1 do
    try
      g:=TPicture.Create;
      g.LoadFromFile(LstIcons[i]);
      LstIcons.Objects[i]:=g;
      LstIcons[i]:=ExtractFileName(LstIcons[i]);
    except
    end;

  Synchronize(@NotifyListener);

  for i:=0 to FlowPanel.ControlCount-1 do
  begin
    AFrmPackage:=FlowPanel.Controls[i] as TFrmPackage;
    IconIdx := LstIcons.IndexOf(UTF8Encode(AFrmPackage.Package.S['package'])+'.png');
    if IconIdx>=0 then
      AFrmPackage.ImgPackage.Picture.Assign(LstIcons.Objects[IconIdx] as TPicture);
    end;
end;

end.

