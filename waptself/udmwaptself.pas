unit uDMWaptSelf;

{$mode objfpc}{$H+}

interface

uses
  Classes, Controls, waptcommon, superobject, httpsend;

type

  { TDMWaptSelf }

  TDMWaptSelf = class(TDataModule)
  private
    FToken:String;
    FLogin:String;
    LockLogin: boolean;
    FLock: TRTLCriticalSection;
    LockToken: boolean;
    FLockLoginDlg: TRTLCriticalSection;
    function GetToken: String;
    function GetLocalLogin: String;
    procedure OnLocalServiceAuth(Sender: THttpSend; var ShouldRetry: Boolean;RetryCount:integer);
  public
    property Login:String read GetLocalLogin write FLogin;
    property Token:String read GetToken;
    function JSONGet(action : String): ISuperObject;
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
  end;

var
  DMWaptSelf: TDMWaptSelf;

implementation

uses IniFiles, Dialogs, Forms,waptutils, uVisLogin, sysutils, FileUtil, uWaptSelfRes, tiscommon;
{$R *.lfm}

{ TDMWaptSelf }

function TDMWaptSelf.GetLocalLogin: String;
begin
  if (FLogin='') then
    Result:=waptutils.AGetUserName;
  Result:=FLogin;
end;

procedure TDMWaptSelf.OnLocalServiceAuth(Sender: THttpSend; var ShouldRetry: Boolean;RetryCount:integer);
var
  LoginDlg: TVisLogin;
  result: String;
begin
  EnterCriticalSection(FLockLoginDlg);
  Try
  begin
    LoginDlg:=TVisLogin.Create(Nil);
    if (FLogin='') then
      LoginDlg.EdUsername.text:=waptutils.AGetUserName
    else
      LoginDlg.EdUsername.text:=FLogin;
    if (RetryCount>1) then
    begin
      SetString(result, PAnsiChar(Sender.Document.Memory), Sender.Document.Size);
      if (result='WRONG_PASSWORD_USERNAME') then
         LoginDlg.WarningText.Caption:=rsWRONG_PASSWORD_USERNAME
      else if (result='NO_RULES') then
         LoginDlg.WarningText.Caption:=rsNO_RULES
      else
          LoginDlg.WarningText.Caption:=result;
      LoginDlg.ImageWarning.Show;
      LoginDlg.WarningText.Show;
      if Screen.PixelsPerInch<>96 then
         LoginDlg.Height:=LoginDlg.Height+(LoginDlg.WarningText.Height-trunc((LoginDlg.WarningText.Height*96)/Screen.PixelsPerInch));
    end
    else
      LoginDlg.Height:=LoginDlg.Height;
    case LoginDlg.ShowModal of
      mrCancel, mrClose:
      begin
        ShouldRetry:=False;
        LockLogin:=true;
        Application.Terminate;
      end;
      mrOK:
      begin
        Sender.UserName:=LoginDlg.EdUsername.text;
        Sender.Password:=LoginDlg.EdPassword.text;
        Login:=LoginDlg.EdUsername.text;
        ShouldRetry:=True;
      end;
    end;
  end
  finally
    FreeAndNil(LoginDlg);
    LeaveCriticalsection(FLockLoginDlg);
  end;
end;

function TDMWaptSelf.JSONGet(action: String): ISuperObject;
begin
  Result:=WAPTLocalJsonGet(action,Login,Token,-1,Nil,0);
end;

constructor TDMWaptSelf.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  InitCriticalSection(FLock);
  InitCriticalSection(FLockLoginDlg);
  FLogin:='';
  FToken:='';
  LockLogin:=false;
  LockToken:=false;
end;

destructor TDMWaptSelf.Destroy;
begin
  DoneCriticalSection(FLockLoginDlg);
  DoneCriticalSection(FLock);
  inherited Destroy;
end;

function TDMWaptSelf.GetToken: String;
var
  iniWaptGet : TIniFile;
  waptservice_localuser:String;
begin
  if not(LockToken) then
  begin
    if (FToken='') then
    begin
      if (LockLogin) then
      begin
        Result:='';
      end
      else
      begin
        EnterCriticalSection(FLock);
        Try
          try
            iniWaptGet:=TIniFile.Create(WaptIniFilename);
            waptservice_localuser := iniWaptGet.ReadString('global','waptservice_user','admin');

            if not CheckOpenPort(waptservice_port,'127.0.0.1',waptservice_timeout*1000) then
              Raise Exception.Create(rsServiceNotRun);

            if (iniWaptGet.ReadString('global','waptservice_password','') = 'NOPASSWORD') then
            begin
              // wait for service to start
              FToken:=UTF8Encode(WAPTLocalJsonGet('login',waptservice_localuser,'NOPASSWORD',-1,@OnLocalServiceAuth,-1).S['token']);
              FLogin:=waptservice_localuser;
            end
            else
              FToken:=UTF8Encode(WAPTLocalJsonGet('login','','',-1,@OnLocalServiceAuth,-1).S['token']);
          except
            if not(LockToken) and (MessageDlg(rsServiceNotRun,mtWarning,mbYesNo,0)<>mrYes) then
            begin
              LockToken:=true;
              Result:='';
              Application.Terminate;
            end
            else
              Result:=GetToken();
          end;
        Finally
          FreeAndNil(iniWaptGet);
          LeaveCriticalSection(FLock);
        end;
      end;
    end;
    Result:=FToken;
  end
  else
    Result:='';
end;


end.

