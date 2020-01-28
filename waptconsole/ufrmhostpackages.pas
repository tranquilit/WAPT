unit uFrmHostPackages;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, ExtCtrls, StdCtrls, Buttons,
  Menus, ActnList, sogrid, SearchEdit, SuperObject,waptcommon;

type

  { TFrmHostPackages }

  TFrmHostPackages = class(TFrame)
    ActionList1: TActionList;
    ActionsImages24: TImageList;
    ButStatusPackagesAll: TButton;
    cbStatusErrors: TCheckBox;
    cbStatusInstall: TCheckBox;
    cbStatusRemove: TCheckBox;
    cbStatusUpgrade: TCheckBox;
    EdSearchHostPackages: TSearchEdit;
    GridHostPackages: TSOGrid;
    ImageList1: TImageList;
    ImgStatusErrors: TImage;
    ImgStatusInstall: TImage;
    ImgStatusRemove: TImage;
    ImgStatusUpgrade: TImage;
    LabInstallLogTitle: TLabel;
    MemoInstallOutput: TMemo;
    MenuItem115: TMenuItem;
    MenuItem19: TMenuItem;
    MenuItem20: TMenuItem;
    MenuItem42: TMenuItem;
    MenuItem53: TMenuItem;
    MenuItem94: TMenuItem;
    Panel5: TPanel;
    panFilterHostPackages: TPanel;
    PopupHostPackages: TPopupMenu;
    SpeedButton2: TSpeedButton;
    Splitter4: TSplitter;
    procedure ActPackagesInstallExecute(Sender: TObject);
    procedure ActPackagesRemoveExecute(Sender: TObject);
    procedure ActPackagesForceInstallExecute(Sender: TObject);
    procedure ActPackagesForgetExecute(Sender: TObject);
  private
    FHostsUUIDs: ISuperObject;
    FWaptServer: IWaptServer;
    FWaptSigner: IWaptSigner;
    procedure SetHostsUUIDs(AValue: ISuperObject);
    procedure SetWaptServer(AValue: IWaptServer);
    procedure SetWaptSigner(AValue: IWaptSigner);
    procedure TriggerPendingActions(APackagesStatusGrid:TSOGrid;title,errortitle:String;Force:Boolean=False);
    procedure TriggerActionOnHostPackages(APackagesStatusGrid:TSOGrid;AAction,title,errortitle:String;Force:Boolean=False);

  public
    property HostsUUIDs: ISuperObject read FHostsUUIDs write SetHostsUUIDs;
    property WaptSigner: IWaptSigner read FWaptSigner write SetWaptSigner;
    property WaptServer: IWaptServer read FWaptServer write SetWaptServer;
  end;

implementation
uses Dialogs,SOUtils,uWaptConsoleRes;
{$R *.lfm}


procedure TFrmHostPackages.ActPackagesInstallExecute(Sender: TObject);
begin
  TriggerActionOnHostPackages(GridHostPackages,
      'trigger_install_packages',rsConfirmPackageInstall,rsPackageInstallError,False)
end;

procedure TFrmHostPackages.ActPackagesRemoveExecute(Sender: TObject);
begin
  TriggerActionOnHostPackages(GridHostPackages,
      'trigger_remove_packages',rsConfirmRmPackagesFromHost,rsPackageRemoveError)
end;

procedure TFrmHostPackages.ActPackagesForceInstallExecute(Sender: TObject);
begin
  TriggerActionOnHostPackages(GridHostPackages,
      'trigger_install_packages',rsConfirmPackageInstall,rsPackageInstallError,True)
end;

procedure TFrmHostPackages.ActPackagesForgetExecute(Sender: TObject);
begin
  TriggerActionOnHostPackages(GridHostPackages,
      'trigger_forget_packages',rsConfirmHostForgetsPackages,rsForgetPackageError,True)
end;

procedure TFrmHostPackages.SetHostsUUIDs(AValue: ISuperObject);
begin
  if FHostsUUIDs=AValue then Exit;
  FHostsUUIDs:=AValue;
end;

procedure TFrmHostPackages.SetWaptServer(AValue: IWaptServer);
begin
  if FWaptServer=AValue then Exit;
  FWaptServer:=AValue;
end;

procedure TFrmHostPackages.SetWaptSigner(AValue: IWaptSigner);
begin
  if FWaptSigner=AValue then Exit;
  FWaptSigner:=AValue;
end;

procedure TFrmHostPackages.TriggerPendingActions(APackagesStatusGrid:TSOGrid;title,errortitle:String;Force:Boolean=False);
var
  sel : ISuperObject;
  PackageStatus, SOAction, SOActions,res,HostUUID:ISuperObject;
  AAction,PackageReq,actions_json,
  signed_actions_json:String;
  VPrivateKeyPassword:Variant;
begin
  if APackagesStatusGrid.Focused then
  begin
    sel := APackagesStatusGrid.SelectedRows;
    if Dialogs.MessageDlg(
       rsConfirmCaption,
       format(title, [IntToStr(sel.AsArray.Length)]),
       mtConfirmation,
       mbYesNoCancel,
       0) = mrYes then
    begin
      try
        SOActions := TSuperObject.Create(stArray);
        // create one signed action per host / package / install_status
        for PackageStatus in sel do
        begin
          case sel.S['install_status'] of
            'TO-INSTALL': begin AAction := 'install';PackageReq := Format('%s(=%s)',[sel.S['package'],sel.S['version']]); end;
            'TO-UPGRADE': begin AAction := 'install';PackageReq := sel.S['package']; end;
            'TO-REMOVE': begin AAction := 'remove';PackageReq := sel.S['package']; end;
            'ERROR': begin AAction := 'install';PackageReq := Format('%s(=%s)',[sel.S['package'],sel.S['version']]); end;
          else
            AAction := '';
          end;

          if AAction<> '' then
            for HostUUID in sel['host'] do
            begin
              SOAction := SO();
              SOAction.S['action'] := AAction;
              SOAction['uuid'] := HostUUID;
              SOAction.B['notify_server'] := True;
              SOAction.B['force'] := Force;
              SOAction['packages'] := SA([PackageReq]);
              SOActions.AsArray.Add(SOAction);
            end;
        end;

        SOActions := WaptSigner.SignJsonData(SOActions);

        //transfer actions as json string to python
        {actions_json := UTF8Encode(SOActions.AsString);
        VPrivateKeyPassword := PyUTF8Decode(dmpython.privateKeyPassword);

        signed_actions_json := VarPythonAsString(DMPython.waptdevutils.sign_actions(
            actions:=actions_json,
            sign_certs := DMPython.WAPT.personal_certificate('--noarg--'),
            sign_key := DMPython.WAPT.private_key(private_key_password := VPrivateKeyPassword)));
        SOActions := SO(signed_actions_json);}

        res := WaptServer.JsonPost('/api/v3/trigger_host_action?timeout=%D',[waptservice_timeout],SOActions);
        if (res<>Nil) and res.AsObject.Exists('success') then
        begin
          if res.AsObject.Exists('msg') then
            ShowMessage(UTF8Encode(res.S['msg']));
        end
        else
          if not res.B['success'] or (res['result'].A['errors'].Length>0) then
            Raise Exception.Create(UTF8Encode(res.S['msg']));
      except
        on E:Exception do
          ShowMessage(Format(errortitle,
              [e.Message]));
      end;
    end;
  end;
end;


procedure TFrmHostPackages.TriggerActionOnHostPackages(
  APackagesStatusGrid: TSOGrid; AAction, title, errortitle: String;
  Force: Boolean);
var
  sel, packages : ISuperObject;
  SOAction, SOActions,res,HostUUID:ISuperObject;
  actions_json,
  signed_actions_json:String;
  VPrivateKeyPassword:Variant;
begin
  sel := APackagesStatusGrid.SelectedRows;
  if Dialogs.MessageDlg(
     rsConfirmCaption,
     format(title, [IntToStr(sel.AsArray.Length), Join(',',HostsUUIDs)]),
     mtConfirmation,
     mbYesNoCancel,
     0) = mrYes then
  begin
    packages := ExtractField(sel,'package');
    try
      SOActions := TSuperObject.Create(stArray);
      for HostUUID in HostsUUIDs do
      begin
        SOAction := SO();
        SOAction.S['action'] := AAction;
        SOAction['uuid'] := HostUUID;
        SOAction.B['notify_server'] := True;
        SOAction.B['force'] := Force;
        SOAction['packages'] := packages;
        SOActions.AsArray.Add(SOAction);
      end;

      //transfer actions as json string to python
      {
      actions_json := UTF8Encode(SOActions.AsString);

      VPrivateKeyPassword := PyUTF8Decode(dmpython.privateKeyPassword);

      signed_actions_json := VarPythonAsString(DMPython.waptdevutils.sign_actions(
          actions:=actions_json,
          sign_certs := DMPython.WAPT.personal_certificate('--noarg--'),
          sign_key := DMPython.WAPT.private_key(private_key_password := VPrivateKeyPassword)));
      SOActions := SO(signed_actions_json);

      res := WAPTServerJsonPost('/api/v3/trigger_host_action?timeout=%D',[waptservice_timeout],SOActions);
      }
      SOActions := WaptSigner.SignJsonData(SOActions);
      res := WaptServer.JsonPost('/api/v3/trigger_host_action?timeout=%D',[waptservice_timeout],SOActions);

      if (res<>Nil) and res.AsObject.Exists('success') then
      begin
        if res.AsObject.Exists('msg') then
          ShowMessage(UTF8Encode(res.S['msg']));
      end
      else
        if not res.B['success'] or (res['result'].A['errors'].Length>0) then
          Raise Exception.Create(UTF8Encode(res.S['msg']));
    except
      on E:Exception do
        ShowMessage(Format(errortitle,
            [ Join(',',packages),e.Message]));
    end;
  end;
end;


end.

