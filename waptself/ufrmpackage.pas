unit uFrmPackage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, ExtCtrls, Menus,
  ActnList, ComCtrls, Buttons, BCListBox, BCLabel, BCMaterialDesignButton,
  superobject, waptcommon, uFrmDetailsPackage;

type

  { TFrmPackage }

  TFrmPackage = class(TFrame)
    ActCancelTask: TAction;
    ActionList1: TActionList;
    BtnCancel: TBCMaterialDesignButton;
    BtnInstallUpgrade: TBCMaterialDesignButton;
    BtnRemove: TBCMaterialDesignButton;
    BCPaperPanel1: TBCPaperPanel;
    ImageDetails: TImage;
    TextWaitInstall: TBCLabel;
    ProgressBarInstall: TProgressBar;
    ImgPackage: TImage;
    LabDescription: TBCLabel;
    LabelProgressionInstall: TBCLabel;
    LabPackageName: TBCLabel;
    LabVersion: TBCLabel;
    LabDate: TBCLabel;
    TimerAutoremove: TTimer;
    TimerInstallRemoveFinished: TTimer;
    procedure ActCancelTaskExecute(Sender: TObject);
    procedure ActInstallUpgradePackage(Sender: TObject);
    procedure ActRemovePackage(Sender: TObject);
    procedure ActTimerInstallRemoveFinished(Sender: TObject);
    procedure ImageDetailsClick(Sender: TObject);
    procedure ImageDetailsMouseEnter(Sender: TObject);
    procedure ImageDetailsMouseLeave(Sender: TObject);
    procedure TimerAutoremoveTimer(Sender: TObject);
  private

    procedure OnUpgradeTriggeredTask(Sender: TObject);
    function Impacted_process():boolean;
    function Accept_Impacted_process():boolean;
  public
    Package : ISuperObject;
    TaskID : Integer;
    FrmDetailsPackageInPanel : TFrmDetailsPackage;
    PanelDetails : TPanel;
    DetailsClicked : boolean;
    ActionPackage : String;
    Autoremove : Boolean;
    LstTasks: TStringList;
    constructor Create(TheOwner: TComponent); override;
    procedure AdjustFont(ALabel:TBCLabel);
    procedure LaunchActionPackage(ActPack:String;Pack:ISuperObject;Force:Boolean);
    procedure CancelTask();
  end;

implementation
uses Graphics,BCTools,
  {$IFDEF WINDOWS}JwaTlHelp32,Windows,{$ENDIF}
  Dialogs, uWAPTPollThreads, uWaptSelfRes, uVisWaptSelf, LCLTranslator, uDMWaptSelf, strutils;
{$R *.lfm}

{ TFrmPackage }

procedure TFrmPackage.ActInstallUpgradePackage(Sender: TObject);
begin
  if Accept_Impacted_process() then
  begin
    LaunchActionPackage(ActionPackage,Package,false);
    BtnInstallUpgrade.Enabled:=false;
    BtnInstallUpgrade.NormalColor:=$00C4C4C4;
    if (TextWaitInstall.Caption = rsActionUpgrade) then
      ActionPackage:='upgrade'
    else
      ActionPackage:='install';
    TextWaitInstall.Caption:=rsWaitingInstall;
    TextWaitInstall.Show;
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
    TextWaitInstall.Caption:=rsWaitingRemove;
    TextWaitInstall.Show;
  end;
end;

procedure TFrmPackage.ActTimerInstallRemoveFinished(Sender: TObject);
begin
  if (ActionPackage='remove') then
  begin
    BtnInstallUpgrade.Caption:=rsActionInstall;
    BtnInstallUpgrade.NormalColor:=clGreen;
    BtnInstallUpgrade.Enabled:=true;
    ActionPackage:='install';
  end
  else
  begin
    BtnRemove.NormalColor:=$005754E0;
    BtnRemove.Enabled:=true;
    ActionPackage:='remove';
    BtnInstallUpgrade.Caption:=rsStatusInstalled;
  end;
  ProgressBarInstall.Position:=0;
  ProgressBarInstall.Hide;
  LabelProgressionInstall.Caption:='0%';
  LabelProgressionInstall.Hide;
  TimerInstallRemoveFinished.Enabled:=false;
  if (Autoremove) then
    TimerAutoremove.Enabled:=true;
end;

procedure TFrmPackage.ImageDetailsClick(Sender: TObject);
begin
  if (not DetailsClicked) then
  begin
    ImageDetails.Picture.LoadFromResourceName(HINSTANCE,'MOINS-BLEU');
    PanelDetails.Show;
    FrmDetailsPackageInPanel.ImgPackage.Picture.Assign(ImgPackage.Picture);
    FrmDetailsPackageInPanel.LabName.Caption:=LabPackageName.Caption;
    FrmDetailsPackageInPanel.LabEditor.Caption:=UTF8Encode(Package.S['editor']);
    FrmDetailsPackageInPanel.LabEditor.AdjustFontForOptimalFill;
    FrmDetailsPackageInPanel.LabLastVersion.Caption:=UTF8Encode(Package.S['version']);
    FrmDetailsPackageInPanel.LabLastVersion.AdjustFontForOptimalFill;
    FrmDetailsPackageInPanel.LabOfficialWebsite.Caption:=UTF8Encode(Package.S['homepage']);
    if FrmDetailsPackageInPanel.LabOfficialWebsite.Caption='' then
      FrmDetailsPackageInPanel.LabOfficialWebsite.Hide
    else
      FrmDetailsPackageInPanel.LabOfficialWebsite.Show;
    FrmDetailsPackageInPanel.LabDescription.Caption:=UTF8Encode(Package.S['description']);
    FrmDetailsPackageInPanel.LabLicence.Caption:=UTF8Encode(Package.S['licence']);
    FrmDetailsPackageInPanel.LabLicence.AdjustFontForOptimalFill;

    if ((package.S['install_status'] = 'OK') and not(package.S['install_version'] >= package.S['version'])) then
    begin
      FrmDetailsPackageInPanel.LabUpgradeFromVersion.Show;
      FrmDetailsPackageInPanel.UpgradeFromVersion.Show;
      FrmDetailsPackageInPanel.LabUpgradeFromVersion.Caption:=UTF8Encode(Package.S['install_version'])
    end
    else
    begin
      FrmDetailsPackageInPanel.LabUpgradeFromVersion.Hide;
      FrmDetailsPackageInPanel.UpgradeFromVersion.Hide;
    end;

    FrmDetailsPackageInPanel.LabImpactedProcess.Caption:=StringReplace(UTF8Encode(Package.S['impacted_process']),',',', ',[rfReplaceAll, rfIgnoreCase]);

    if (Package.I['installed_size']<>0) then
      FrmDetailsPackageInPanel.LabSizeInstalled.Caption:=IntToStr(Round(Package.I['installed_size']/1024))+' kB ( '+IntToStr(Package.I['installed_size'])+' bytes )'
    else
      FrmDetailsPackageInPanel.LabSizeInstalled.Caption:='';
    FrmDetailsPackageInPanel.LabSizeInstalled.AdjustFontForOptimalFill;
    if (Package.I['size']<>0) then
      FrmDetailsPackageInPanel.LabSize.Caption:=IntToStr(Round(Package.I['size']/1024))+' kB ( '+IntToStr(Package.I['size'])+' bytes )'
    else
      FrmDetailsPackageInPanel.LabSize.Caption:='';
    FrmDetailsPackageInPanel.LabSize.AdjustFontForOptimalFill;
    FrmDetailsPackageInPanel.LabMaintainer.Caption:=UTF8Encode(Package.S['maintainer']);
    FrmDetailsPackageInPanel.LabMaintainer.AdjustFontForOptimalFill;
    FrmDetailsPackageInPanel.LabPackageName.Caption:=UTF8Encode(Package.S['package']);
    FrmDetailsPackageInPanel.LabPackageName.AdjustFontForOptimalFill;
    FrmDetailsPackageInPanel.LabRepository.Caption:=UTF8Encode(Package.S['repo']);
    FrmDetailsPackageInPanel.LabRepository.AdjustFontForOptimalFill;
    FrmDetailsPackageInPanel.LabSigner.Caption:=UTF8Encode(Package.S['signer']);
    FrmDetailsPackageInPanel.LabSigner.AdjustFontForOptimalFill;
    FrmDetailsPackageInPanel.LabDependency.Caption:=ReplaceStr(UTF8Encode(Package.S['depends']),',',','+chr(13));
    if (FrmDetailsPackageInPanel.LabDependency.Caption='') then
      FrmDetailsPackageInPanel.LabDependency.Hide
    else
      FrmDetailsPackageInPanel.LabDependency.Show;
    FrmDetailsPackageInPanel.LabConflicts.Caption:=UTF8Encode(Package.S['conflicts']);
    FrmDetailsPackageInPanel.LabConflicts.AdjustFontForOptimalFill;
    FrmDetailsPackageInPanel.LabSection.Caption:=UTF8Encode(Package.S['section']);
    FrmDetailsPackageInPanel.LabSection.AdjustFontForOptimalFill;
    FrmDetailsPackageInPanel.LabSignatureDate.Caption:=LabDate.Caption;
    FrmDetailsPackageInPanel.LabSignatureDate.AdjustFontForOptimalFill;
    FrmDetailsPackageInPanel.LabCategories.Caption:=UTF8Encode(Package.S['categories']);
    FrmDetailsPackageInPanel.LabCategories.AdjustFontForOptimalFill;
    VisWaptSelf.ChangeIconMinusByPlusOnFrames();
    DetailsClicked:=not(DetailsClicked);
  end
  else
  begin
    VisWaptSelf.ActHideDetailsClick.Execute;
    ImageDetails.Picture.LoadFromResourceName(HINSTANCE,'PLUS2');
  end;
end;

procedure TFrmPackage.ImageDetailsMouseEnter(Sender: TObject);
begin
  if (DetailsClicked) then
    ImageDetails.Picture.LoadFromResourceName(HINSTANCE,'MOINS-BLEU')
  else
    ImageDetails.Picture.LoadFromResourceName(HINSTANCE,'PLUS2');
end;

procedure TFrmPackage.ImageDetailsMouseLeave(Sender: TObject);
begin
  if (DetailsClicked) then
    ImageDetails.Picture.LoadFromResourceName(HINSTANCE,'MOINS-BLANC')
  else
    ImageDetails.Picture.LoadFromResourceName(HINSTANCE,'PLUS-BLEU-FONCE');
end;

procedure TFrmPackage.TimerAutoremoveTimer(Sender: TObject);
begin
  TimerAutoremove.Enabled:=false;
  Self.Destroy;
end;

function TFrmPackage.Impacted_process(): boolean;
{$IFDEF WINDOWS}
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
{$ELSE}
begin
end;
{$ENDIF}
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
  DetailsClicked:=false;
  {$IFDEF UNIX}
  LabPackageName.FontEx.Name:='default';
  {$ENDIF}
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
  TTriggerWaptserviceAction.Create(format('%s.json?package=%s%s',[ActPack,Pack.S['package'],StrForce]),@OnUpgradeTriggeredTask,DMWaptSelf.Login,DMWaptSelf.Token,Nil);
end;

procedure TFrmPackage.CancelTask();
begin
  if TaskID<>0 then
  begin
    DMWaptSelf.JSONGet(Format('cancel_task.json?id=%d',[TaskID]));
    LstTasks.Delete(LstTasks.IndexOf(UTF8Encode(Package.S['package'])));
    TaskID:=0;
    if (ActionPackage='install') then
    begin
      BtnInstallUpgrade.Caption:=rsActionInstall;
      BtnInstallUpgrade.NormalColor:=clGreen;
      BtnInstallUpgrade.Enabled:=true;
      ActionPackage:='install';
    end
    else
      if (ActionPackage='upgrade') then
      begin
        BtnInstallUpgrade.Caption:=rsActionUpgrade;
        BtnInstallUpgrade.NormalColor:=clGreen;
        BtnInstallUpgrade.Enabled:=true;
        ActionPackage:='install';
      end
      else
      begin
        BtnRemove.NormalColor:=$005754E0;
        BtnRemove.Enabled:=true;
        ActionPackage:='remove';
        BtnInstallUpgrade.Caption:=rsStatusInstalled;
      end;
    ProgressBarInstall.Position:=0;
    ProgressBarInstall.Style:=pbstMarquee;
    ProgressBarInstall.Hide;
    LabelProgressionInstall.Caption:='0%';
    LabelProgressionInstall.Hide;
    TextWaitInstall.Hide;
    BtnCancel.Hide;
  end;
end;

procedure TFrmPackage.OnUpgradeTriggeredTask(Sender: TObject);
begin
  if (ActionPackage='remove') then
    TaskID:=(Sender as TTriggerWaptserviceAction).Res.O['0'].I['id']
  else
    TaskID:=(Sender as TTriggerWaptserviceAction).Res.I['id'];
  LstTasks.AddObject(UTF8Encode(Package.S['package']),TObject(PtrUInt(TaskID)));
  BtnCancel.Show;
end;

procedure TFrmPackage.ActCancelTaskExecute(Sender: TObject);
begin
  CancelTask();
end;



end.
