unit uFrmPackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ExtCtrls, Menus,
  ActnList, ComCtrls, Buttons, BCListBox, BCLabel, BCMaterialDesignButton,
  superobject, waptcommon;

type

  { TFrmPackage }

  TFrmPackage = class(TFrame)
    Action1: TAction;
    ActionList1: TActionList;
    BtnCancel: TBCMaterialDesignButton;
    BtnInstallUpgrade: TBCMaterialDesignButton;
    BtnRemove: TBCMaterialDesignButton;
    BCPaperPanel1: TBCPaperPanel;
    ProgressBarInstall: TProgressBar;
    ImgPackage: TImage;
    LabDescription: TBCLabel;
    LabelProgressionInstall: TBCLabel;
    LabInstallVersion: TBCLabel;
    LabPackageName: TBCLabel;
    LabVersion: TBCLabel;
    LabMaintainer: TBCLabel;
    LabDate: TBCLabel;
    TextWaitInstall: TStaticText;
    TimerAutoremove: TTimer;
    TimerInstallRemoveFinished: TTimer;
    procedure ActCancelTaskExecute(Sender: TObject);
    procedure ActInstallUpgradePackage(Sender: TObject);
    procedure ActRemovePackage(Sender: TObject);
    procedure ActTimerInstallRemoveFinished(Sender: TObject);
    procedure TimerAutoremoveTimer(Sender: TObject);
  private
    procedure OnUpgradeTriggeredTask(Sender: TObject);
    function Impacted_process():boolean;
    function Accept_Impacted_process():boolean;
  public
    Package : ISuperObject;
    TaskID : Integer;
    login : String;
    password : String;

    OnLocalServiceAuth : THTTPSendAuthorization;
    ActionPackage : String;
    Autoremove : Boolean;
    LstTasks: TStringList;
    constructor Create(TheOwner: TComponent); override;
    procedure AdjustFont(ALabel:TBCLabel);
    procedure LaunchActionPackage(ActPack:String;Pack:ISuperObject;Force:Boolean);
    procedure CancelTask();
  end;

resourcestring
  rsImpacted_processes = 'Some processes (see list below) may be closed during installation/removal.'+Chr(13)+'Do you want to continue ?'+Chr(13)+'Impacted processes : %s';
  rsErrorTriggeringTask = 'Error triggering action: %s';

implementation
uses Graphics,BCTools,JwaTlHelp32,Windows,Dialogs, uWAPTPollThreads;
{$R *.lfm}

{ TFrmPackage }

procedure TFrmPackage.ActInstallUpgradePackage(Sender: TObject);
begin
  if Accept_Impacted_process() then
  begin
    LaunchActionPackage(ActionPackage,Package,false);
    BtnInstallUpgrade.Enabled:=false;
    BtnInstallUpgrade.NormalColor:=$00C4C4C4;
    TextWaitInstall.Caption:='Waiting for install...';
    TextWaitInstall.Show;
    ActionPackage:='install';
    LabDescription.Hide;

  end;
end;

procedure TFrmPackage.ActRemovePackage(Sender: TObject);
begin
  if Accept_Impacted_process() then
  begin
    ActionPackage:='remove';
    LaunchActionPackage('remove',Package,false);
    BtnRemove.Enabled:=false;
    BtnRemove.NormalColor:=$00C4C4C4;
    TextWaitInstall.Caption:='Waiting for uninstall...';
    TextWaitInstall.Show;
    LabDescription.Hide;
  end;
end;

procedure TFrmPackage.ActTimerInstallRemoveFinished(Sender: TObject);
begin
  if (ActionPackage='remove') then
  begin
    BtnInstallUpgrade.Caption:='Install';
    BtnInstallUpgrade.NormalColor:=clGreen;
    BtnInstallUpgrade.Enabled:=true;
    ActionPackage:='install';
  end
  else
  begin
    BtnRemove.NormalColor:=clRed;
    BtnRemove.Enabled:=true;
    ActionPackage:='remove';
    BtnInstallUpgrade.Caption:='Installed';
  end;
  ProgressBarInstall.Position:=0;
  ProgressBarInstall.Hide;
  LabelProgressionInstall.Caption:='0%';
  LabelProgressionInstall.Hide;
  TimerInstallRemoveFinished.Enabled:=false;
  LabDescription.Show;
  if (Autoremove) then
    TimerAutoremove.Enabled:=true;
end;

procedure TFrmPackage.TimerAutoremoveTimer(Sender: TObject);
begin
  TimerAutoremove.Enabled:=false;
  Self.Destroy;
end;

function TFrmPackage.Impacted_process(): boolean;
var
  ContinueLoop: boolean;
  FSnapshotHandle: THandle;
  FProcessEntry32: TProcessEntry32;
  ExeFileName:String;
  ListExe:TStringList;
begin
  FSnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  FProcessEntry32.dwSize := SizeOf(FProcessEntry32);
  ContinueLoop := Process32First(FSnapshotHandle, FProcessEntry32);
  Result:=False;
  ListExe:=TStringList.Create;
  ListExe.Delimiter:=',';
  ListExe.DelimitedText:=UTF8Encode(Package.S['impacted_process']);

  while ContinueLoop do
  begin
    for ExeFileName in ListExe do
      if ((UpperCase(ExtractFileName(FProcessEntry32.szExeFile)) = UpperCase(Trim(ExeFileName))) or (UpperCase(FProcessEntry32.szExeFile) = UpperCase(Trim(ExeFileName)))) then
      begin
        ListExe.Free;
        CloseHandle(FSnapshotHandle);
        Exit(True);
      end;
    ContinueLoop:=Process32Next(FSnapshotHandle,FProcessEntry32);
  end;
  ListExe.Free;
  CloseHandle(FSnapshotHandle);
end;

function TFrmPackage.Accept_Impacted_process(): boolean;
begin
  if Impacted_process()=false then
    Exit(True)
  else
  begin
    Result:=(MessageDlg(Format(rsImpacted_processes,[Package.S['impacted_process']]),mtWarning,mbYesNo,0)= mrYes);
  end;
end;

constructor TFrmPackage.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  ProgressBarInstall.Hide;
  Autoremove:=false;
  TaskID:=0;
end;

procedure TFrmPackage.AdjustFont(ALabel: TBCLabel);
var
  PreferredWidth, PreferredHeight: integer;
  newfs:Integer;
begin
  With ALabel  do
  begin
    CalculateTextSize(Caption, FontEx, PreferredWidth, PreferredHeight);
    if FontEx.WordBreak then
    begin
      if (PreferredHeight > Height) then
        newfs := (Height  * FontEx.Height) div PreferredHeight
      else
        newfs := FontEx.Height;
    end
    else
    begin
      if (PreferredWidth > Width) then
        newfs := (Width  * FontEx.Height) div PreferredWidth
      else
        newfs := FontEx.Height;
    end;

    if newfs <> FontEx.Height then
      FontEx.Height := newfs;
  end;
end;

procedure TFrmPackage.LaunchActionPackage(ActPack:String;Pack: ISuperObject;Force:Boolean);
var
  StrForce:string;
begin
  StrForce:='';
  if Force then StrForce:='&force=1';
  ProgressBarInstall.Style:=pbstMarquee;
  TTriggerWaptserviceAction.Create(format('%s.json?package=%s%s',[ActPack,Pack.S['package'],StrForce]),@OnUpgradeTriggeredTask,login,password,OnLocalServiceAuth);
end;

procedure TFrmPackage.CancelTask();
begin
  if TaskID<>0 then
  begin
    WAPTLocalJsonGet(Format('cancel_task.json?id=%d',[TaskID]),login,password,-1,OnLocalServiceAuth,2);
    LstTasks.Delete(LstTasks.IndexOf(UTF8Encode(Package.S['package'])));
    TaskID:=0;
    if (ActionPackage='install') then
    begin
      BtnInstallUpgrade.Caption:='Install';
      BtnInstallUpgrade.NormalColor:=clGreen;
      BtnInstallUpgrade.Enabled:=true;
      ActionPackage:='install';
    end
    else
    begin
      BtnRemove.NormalColor:=clRed;
      BtnRemove.Enabled:=true;
      ActionPackage:='remove';
      BtnInstallUpgrade.Caption:='Installed';
    end;
    ProgressBarInstall.Position:=0;
    ProgressBarInstall.Style:=pbstMarquee;
    ProgressBarInstall.Hide;
    LabelProgressionInstall.Caption:='0%';
    LabelProgressionInstall.Hide;
    TextWaitInstall.Hide;
    BtnCancel.Hide;
    LabDescription.Show;
  end;
end;

procedure TFrmPackage.OnUpgradeTriggeredTask(Sender: TObject);
begin
  if (ActionPackage='remove') then
    TaskID:=(Sender as TTriggerWaptserviceAction).Res.O['0'].I['id']
  else
    TaskID:=(Sender as TTriggerWaptserviceAction).Res.I['id'];
  LstTasks.AddObject(UTF8Encode(Package.S['package']),TObject(Pointer(TaskID)));
  BtnCancel.Show;
end;

procedure TFrmPackage.ActCancelTaskExecute(Sender: TObject);
begin
  CancelTask();
end;



end.
