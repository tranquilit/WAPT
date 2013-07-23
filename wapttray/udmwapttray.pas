unit uDMWAPTTray;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, ExtCtrls, Menus, ActnList, Controls,uniqueinstance;

type

  TTrayMode = (tmOK,tmRunning,tmUpgrades,tmErrors);

  { TDMWaptTray }
  TDMWaptTray = class(TDataModule)
    ActConfigure: TAction;
    ActForceRegister: TAction;
    ActSessionSetup: TAction;
    ActLocalInfo: TAction;
    ActWaptUpgrade: TAction;
    ActLaunchWaptConsole: TAction;
    ActionList1: TActionList;
    ActQuit: TAction;
    ActShowMain: TAction;
    ActShowStatus: TAction;
    ActUpdate: TAction;
    ActUpgrade: TAction;
    MenuItem10: TMenuItem;
    MenuItem12: TMenuItem;
    MenuItem13: TMenuItem;
    MenuItem14: TMenuItem;
    MenuItem15: TMenuItem;
    MenuItem3: TMenuItem;
    MenuItem11: TMenuItem;
    MenuItem7: TMenuItem;
    MenuItem8: TMenuItem;
    MenuItem9: TMenuItem;
    MenuWaptVersion: TMenuItem;
    TrayUpdate: TImageList;
    TrayRunning: TImageList;
    MenuItem1: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    MenuItem6: TMenuItem;
    PopupMenu1: TPopupMenu;
    TrayIcon1: TTrayIcon;
    UniqueInstance1:TUniqueInstance;
    procedure ActConfigureExecute(Sender: TObject);
    procedure ActForceRegisterExecute(Sender: TObject);
    procedure ActLaunchWaptConsoleExecute(Sender: TObject);
    procedure ActLaunchWaptConsoleUpdate(Sender: TObject);
    procedure ActLocalInfoExecute(Sender: TObject);
    procedure ActQuitExecute(Sender: TObject);
    procedure ActSessionSetupExecute(Sender: TObject);
    procedure ActShowStatusExecute(Sender: TObject);
    procedure ActUpdateExecute(Sender: TObject);
    procedure ActUpgradeExecute(Sender: TObject);
    procedure ActWaptUpgradeExecute(Sender: TObject);
    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleDestroy(Sender: TObject);
    procedure PopupMenu1Popup(Sender: TObject);
    procedure TrayIcon1DblClick(Sender: TObject);
  private
    procedure SetTrayIcon(idx: integer);
    function WaptConsoleFileName: String;
    { private declarations }
  public
    { public declarations }
    check_thread:TThread;
    checkinterval:Integer;
    trayMode:TTrayMode;
  end;

var
  DMWaptTray: TDMWaptTray;

implementation
uses LCLIntf,Forms,dialogs,windows,superobject,graphics,tiscommon,waptcommon,tisinifiles,soutils,UnitRedirect;

{$R *.lfm}
type

  { TCheckThread }

  TCheckThread = Class(TThread)
    public
      new_updates,new_runstatus : String;
      new_hint:String;
      new_balloon:String;
      new_traymode:TTrayMode;
      icon_idx:integer;
      previous_runstatus:String;
      DMTray:TDMWaptTray;
      previous_upgrades,upgrades,running,errors : ISuperObject;
      checkinterval:integer;
      force_balloon :Boolean;
      procedure Execute; override;
      procedure SetTrayStatus;
      procedure ResetPreviousUpgrades;
  end;

{ TCheckThread }

procedure TCheckThread.Execute;
var
  upgrade_status,new_runstatus_so:ISuperObject;
begin
  repeat
    try
      new_hint :='';
      new_balloon:='';
      icon_idx:=-1;

      if previous_upgrades=Nil then
        previous_upgrades := TSuperObject.Create(stArray);

      upgrade_status := Nil;
      running := Nil;
      upgrades := Nil;
      errors := Nil;

      //test running tasks first
      new_runstatus_so := WAPTLocalJsonGet('runstatus');
      if (new_runstatus_so<>Nil) and (new_runstatus_so.AsArray.Length>0)  then
        new_runstatus := new_runstatus_so['0'].S['value']
      else
        new_runstatus := 'Impossible de récupérer l''action en cours';
      if new_runstatus<>'' then
      begin
        new_traymode:=tmRunning;
        new_hint:=new_runstatus;
      end
      else
      begin
        // Then check if new upgrades are available
        upgrade_status := WAPTLocalJsonGet('checkupgrades');
        running := upgrade_status['running_tasks'];
        upgrades := upgrade_status['upgrades'];
        errors := upgrade_status['errors'];

        if (running<>Nil) and (running.AsArray.Length>0) then
        begin
          new_traymode:=tmRunning;
          new_hint:='Installation en cours : '+running.AsString;
        end
        else
        if (upgrades<>Nil) and (upgrades.AsArray.Length>0) then
        begin
          new_traymode:=tmUpgrades;
          new_hint:='Mises à jour disponibles pour : '+#13#10+soutils.join(#13#10,upgrades);
        end
        else
        if (errors<>Nil) and (errors.AsArray.Length>0) then
        begin
          new_hint:='Erreurs : '+#13#10+ Join(#13#10,errors);
          new_traymode:=tmErrors;
        end
        else
        begin
          new_hint:='Système à jour';
          new_traymode:=tmOK;
        end;
      end;

      // show balloon if run_status has changed
      if (new_runstatus<>previous_runstatus) and (new_runstatus<>'') then
      begin
        new_balloon:=new_runstatus;
        previous_runstatus:=new_runstatus;
      end
      else
      if (upgrades<>Nil) and (previous_upgrades<>Nil) and ((upgrades.AsJSon<>previous_upgrades.AsJSon) or force_balloon) then
      begin
        if upgrades.AsArray.Length>previous_upgrades.AsArray.Length then
          new_balloon:='Mises à jour disponibles pour : '+#13#10+soutils.join(#13#10,upgrades)
        else
          if (running<>Nil) and (running.AsArray.Length>0) then
            new_balloon:='Installation en cours : '+running.AsString
          else if (errors<>Nil) and (errors.AsArray.Length>0) then
            new_balloon:='Erreurs : '+#13#10+ Join(#13#10,errors)
          else if upgrades.AsArray.Length=0 then
            new_balloon:='Système à jour';
        previous_upgrades:= upgrades;
        force_balloon := False;
      end;
      Synchronize(@SetTrayStatus);
    except
      on e:Exception do
      begin
        new_hint:='Impossible d''obtenir le status de mise à jour'+#13#10+e.Message;
        new_traymode:=tmErrors;
        Synchronize(@SetTrayStatus);
      end;
    end;
    if not Terminated then
      Sleep(CheckInterval);
  until Terminated;
end;

procedure TCheckThread.SetTrayStatus;
begin
  if new_traymode<>DMTray.trayMode  then
  begin
    if new_traymode = tmOK then
      DMTray.SetTrayIcon(0)
    else
    if new_traymode = tmRunning then
    begin
      DMTray.TrayIcon1.Icons := DMTray.TrayRunning;
      DMTray.TrayIcon1.Animate:=True;
    end
    else
    if new_traymode = tmUpgrades then
    begin
      DMTray.TrayIcon1.Icons := DMTray.TrayUpdate;
      DMTray.TrayIcon1.Animate:=True;
    end
    else
    if new_traymode = tmErrors then
    begin
      DMTray.TrayIcon1.Icons := DMTray.TrayUpdate;
      DMTray.TrayIcon1.Animate:=False;
      DMTray.SetTrayIcon(1);
    end;
    DMTray.trayMode := new_traymode;
  end;

  if new_hint<>'' then
    DMTray.TrayIcon1.Hint:=new_hint;

  if new_balloon<>'' then
  begin
    DMTray.TrayIcon1.BalloonHint:=new_balloon;
    DMTray.TrayIcon1.ShowBalloonHint;
  end;
end;

procedure TCheckThread.ResetPreviousUpgrades;
begin
  previous_upgrades := TSuperObject.Create(stArray);
  force_balloon:=True;
end;

{ TVisWAPTTray }

procedure TDMWaptTray.ActShowStatusExecute(Sender: TObject);
begin
  OpenURL(GetWaptLocalURL+'/status');
end;

procedure TDMWaptTray.ActUpdateExecute(Sender: TObject);
begin
  TCheckThread(check_thread).Synchronize(@TCheckThread(check_thread).ResetPreviousUpgrades);
  OpenURL(GetWaptLocalURL+'/update');

  TrayIcon1.BalloonHint:='Mise à jour des logiciels disponibles lancée';
  TrayIcon1.ShowBalloonHint;
end;

procedure TDMWaptTray.ActUpgradeExecute(Sender: TObject);
var
  res : String;
begin
  TCheckThread(check_thread).Synchronize(@TCheckThread(check_thread).ResetPreviousUpgrades);
  res := httpGetString(GetWaptLocalURL+'/upgrade');
  if pos('ERROR',uppercase(res))<=0 then
    TrayIcon1.BalloonHint:='Mise à jour des logiciels lancée en tâche de fond...'
  else
    TrayIcon1.BalloonHint:='Erreur au lancement de la mise à jour des logiciels...';
  TrayIcon1.ShowBalloonHint;
end;

procedure TDMWaptTray.ActWaptUpgradeExecute(Sender: TObject);
var
  res : String;
begin
  TCheckThread(check_thread).Synchronize(@TCheckThread(check_thread).ResetPreviousUpgrades);
  res := httpGetString(GetWaptLocalURL+'/waptupgrade');
  TrayIcon1.BalloonHint:='Mise à jour du logiciel WAPT lancée en arrière plan...';
  TrayIcon1.ShowBalloonHint;
end;

procedure TDMWaptTray.DataModuleCreate(Sender: TObject);
begin
  checkinterval:=IniReadInteger(WaptIniFilename,'Global','tray_check_interval')*1000;
  if checkinterval=0 then
    checkinterval:=10000;

  check_thread :=  TCheckThread.Create(True);
  TCheckThread(check_thread).DMTray := Self;
  TCheckThread(check_thread).checkinterval:=checkinterval;
  check_thread.Resume;
end;

procedure TDMWaptTray.DataModuleDestroy(Sender: TObject);
begin
  TerminateThread(check_thread.Handle,0);
  FreeAndNil(check_thread);
end;

procedure TDMWaptTray.PopupMenu1Popup(Sender: TObject);
begin
  MenuWaptVersion.Caption:=GetApplicationVersion(WaptgetPath);
end;

procedure TDMWaptTray.ActConfigureExecute(Sender: TObject);
begin
  OpenDocument(WaptIniFilename);
end;

procedure TDMWaptTray.ActForceRegisterExecute(Sender: TObject);
var
  res : String;
begin
  TCheckThread(check_thread).Synchronize(@TCheckThread(check_thread).ResetPreviousUpgrades);
  res := httpGetString(GetWaptLocalURL+'/register');
  TrayIcon1.BalloonHint:='Enregistrement de l''ordinateur lancé en arrière plan...';
  TrayIcon1.ShowBalloonHint;
end;

procedure TDMWaptTray.ActLaunchWaptConsoleExecute(Sender: TObject);
var
  cmd:String;
begin
  cmd := WaptConsoleFileName;
  ShellExecute(0,Pchar('open'),PChar(cmd),Nil,Nil,0);
end;

function TDMWaptTray.WaptConsoleFileName: String;
begin
  result:=AppendPathDelim(ExtractFileDir(ParamStr(0)))+'waptconsole.exe';
end;

procedure TDMWaptTray.ActLaunchWaptConsoleUpdate(Sender: TObject);
begin
  //ActLaunchWaptConsole.Enabled:=FileExists(WinapticFileName);
end;

procedure TDMWaptTray.ActLocalInfoExecute(Sender: TObject);
begin
  ShowMessage(GetCurrentUserSid);
end;

procedure TDMWaptTray.ActQuitExecute(Sender: TObject);
begin
  check_thread.Terminate;
  Application.Terminate;
end;

procedure TDMWaptTray.ActSessionSetupExecute(Sender: TObject);
var
  status:integer;
  res : String;
begin
  try
    res := Sto_RedirectedExecute(WaptgetPath+' session-setup ALL','',120*1000);
    ShowMessage('Configuration des paquets pour la session utilisateur effectuée')
  except
    MessageDlg('Erreur','Erreur lors de la configuration des paquets pour la session utilisateur',mtError,[mbOK],0);
  end
end;

procedure TDMWaptTray.SetTrayIcon(idx:integer);
var
  lBitmap: TBitmap;
begin
  TrayIcon1.Animate:=False;
  lBitmap := TBitmap.Create;
  try
    TrayUpdate.GetBitmap(idx, lBitmap);
    TrayIcon1.Icon.Assign(lBitmap);
    TrayIcon1.InternalUpdate();
  finally
    lBitmap.Free;
  end;
end;


procedure TDMWaptTray.TrayIcon1DblClick(Sender: TObject);
var
  res:String;
begin
  TCheckThread(check_thread).Synchronize(@TCheckThread(check_thread).ResetPreviousUpgrades);
  res := httpGetString(GetWaptLocalURL+'/updatebg');
  if pos('ERROR',uppercase(res))<=0 then
    TrayIcon1.BalloonHint:='Vérification en cours...'
  else
    TrayIcon1.BalloonHint:='Erreur au lancement de la vérification...';
  TrayIcon1.ShowBalloonHint;
end;

end.

