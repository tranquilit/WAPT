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

uses IniFiles, Dialogs, Forms,waptwinutils, uVisLogin, sysutils, FileUtil, uWaptSelfRes;
{$R *.lfm}

{ TDMWaptSelf }

function TDMWaptSelf.GetLocalLogin: String;
begin
  if (FLogin='') then
    Result:=waptwinutils.AGetUserName;
  Result:=FLogin;
end;

procedure TDMWaptSelf.OnLocalServiceAuth(Sender: THttpSend; var ShouldRetry: Boolean;RetryCount:integer);
var
  LoginDlg: TVisLogin;
begin
  EnterCriticalSection(FLockLoginDlg);
  Try
  begin
    LoginDlg:=TVisLogin.Create(Nil);
    if (FLogin='') then
      LoginDlg.EdUsername.text:=waptwinutils.AGetUserName
    else
      LoginDlg.EdUsername.text:=FLogin;
    if (RetryCount>1) then
    begin
      LoginDlg.ImageWarning.Show;
      LoginDlg.WarningText.Show;
    end
    else
      LoginDlg.Height:=LoginDlg.Height-5-16;
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
            if (iniWaptGet.ReadString('global','waptservice_password','') = 'NOPASSWORD') then
            begin
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

