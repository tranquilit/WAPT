unit uviswaptdeploy;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons, ActnList, sogrid, db,superobject,soutils;

type

  { Tviswaptdeploy }

  Tviswaptdeploy = class(TForm)
    ActDeployWapt: TAction;
    ActStop: TAction;
    ActionList1: TActionList;
    BitBtn2: TBitBtn;
    Button1: TButton;
    Button5: TButton;
    Datasource1: TDatasource;
    EdDomaine: TLabeledEdit;
    EdDomainUser: TLabeledEdit;
    EdDomainPassword: TLabeledEdit;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Memo1: TMemo;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel3: TPanel;
    Panel4: TPanel;
    ProgressGrid: TSOGrid;
    procedure ActDeployWaptExecute(Sender: TObject);
    procedure ActStopExecute(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { private declarations }
    Stopped : Boolean;
  public
    { public declarations }
  end;

var
  viswaptdeploy: Tviswaptdeploy;

implementation
uses tiscommon,waptcommon;
{$R *.lfm}

{ Tviswaptdeploy }

procedure Tviswaptdeploy.FormCreate(Sender: TObject);
begin
  EdDomaine.Text := GetDomainName;
end;

procedure Tviswaptdeploy.ActDeployWaptExecute(Sender: TObject);
var
  i: Integer;
  host,hosts, res : ISuperObject;
begin
  Stopped := False;

  hosts := TSuperObject.Create(stArray);
  for i:=0 to Memo1.Lines.Count - 1 do
  begin
    host := SO(['computer_fqdn',Memo1.Lines[i],'status','','message','']);
    host.S['auth.username'] := EdDomainUser.Text;
    host.S['auth.password'] := EdDomainPassword.Text;
    host.S['auth.domain'] := EdDomaine.Text;
    hosts.AsArray.Add(host);
  end;

  ProgressGrid.Data := hosts;
  for host in hosts do
  begin
    if Stopped  then
      Break;
    host.S['status'] := 'STARTED';
    ProgressGrid.Refresh;
    //Application.ProcessMessages;
    try
      res := WAPTServerJsonPost('/deploy_wapt', host, WaptUseLocalConnectionProxy);
      host['message'] := res['message'];
      host['status'] := res['status'];
      ProgressGrid.Refresh;
      //Application.ProcessMessages;
    except
      on E:Exception do
      begin
        host.S['status'] := 'ERROR';
        host.S['message'] := e.Message;
        ProgressGrid.Refresh;
        //Application.ProcessMessages;
      end;
    end;
  end;
end;

procedure Tviswaptdeploy.ActStopExecute(Sender: TObject);
begin
  Stopped := True;
end;


end.

