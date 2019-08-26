unit uviseditcreaterule;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons;

type

  { TFormEditRule }

  TFormEditRule = class(TForm)
    BitBtnOk: TBitBtn;
    BitBtnCancel: TBitBtn;
    ComboBoxCondition: TComboBox;
    ComboBoxSites: TComboBox;
    EditName: TEdit;
    EditValue: TEdit;
    EditRepoUrl: TEdit;
    LabValue: TLabel;
    LabName: TLabel;
    LabCondition: TLabel;
    LabRepoURL: TLabel;
    procedure ComboBoxConditionChange(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    function CanOK():Boolean;
  public
  end;

var
  FormEditRule: TFormEditRule;

implementation

uses
  RegExpr, uWaptConsoleRes, superobject,waptcommon;

{$R *.lfm}

{ TFormEditRule }

procedure TFormEditRule.FormShow(Sender: TObject);
begin
  MakeFullyVisible();
end;

procedure TFormEditRule.ComboBoxConditionChange(Sender: TObject);
var
  Sites, Site : ISuperObject;
begin
  if (ComboBoxCondition.ItemIndex<>-1) and (ComboBoxCondition.Items[ComboBoxCondition.ItemIndex]=rsSite) then
  begin
    if (ComboBoxSites.Items.Count=0) then
    begin
      Sites:=WAPTServerJsonGet('api/v3/get_ad_sites',[])['result'];
      if Assigned(Sites) then
        for Site in Sites do
            ComboBoxSites.Items.Add(Site.AsString{%H-});
    end;
    ComboBoxSites.Visible:=true;
    EditValue.Visible:=false;
  end
  else
  begin
      ComboBoxSites.Visible:=false;
      EditValue.Visible:=true;
  end;
  BitBtnOk.Enabled:=CanOk();
end;

procedure TFormEditRule.FormCreate(Sender: TObject);
begin
  ComboBoxCondition.Sorted:=True;
  ComboBoxCondition.Clear;
  ComboBoxCondition.Items.Add(rsAgentIP);
  ComboBoxCondition.Items.Add(rsHostname);
  ComboBoxCondition.Items.Add(rsDomain);
  ComboBoxCondition.Items.Add(rsSite);
  ComboBoxCondition.Items.Add(rsPublicIP);
end;

function TFormEditRule.CanOK(): Boolean;
var
  RegexObj : TRegExpr;
  ComboBoxValue : String;
begin
  if (EditName.Caption='') or (ComboBoxCondition.ItemIndex=-1) or (EditRepoUrl.Caption='') then
    Exit(False)
  else
    begin
      RegexObj:=TRegExpr.Create('^(http|https)://.+');
      if RegexObj.Exec(EditRepoUrl.Text) then
      begin
        FreeAndNil(RegexObj);
        ComboBoxValue:=ComboBoxCondition.Items[ComboBoxCondition.ItemIndex];
        if (ComboBoxValue=rsAgentIP) or (ComboBoxValue=rsPublicIP) then
        begin
          RegexObj:=TRegExpr.Create('^((\d){1,3}\.){3}(\d){1,3}\/(\d){1,2}$');
          if RegexObj.Exec(EditValue.Text) and (EditValue.Text<>'') then
          begin
            FreeAndNil(RegexObj);
            Exit(True);
          end
          else
          begin
            FreeAndNil(RegexObj);
            Exit(False);
          end;
        end;
        if (ComboBoxValue=rsDomain) then
           Exit((Pos('.',EditValue.Text)>0) and (EditValue.Text<>''));
        if (ComboBoxValue=rsSite) then
        begin
          if (ComboBoxSites.ItemIndex<>-1) then
             Exit(True)
          else
            Exit(False);
        end;
        Exit(True);
      end
      else
      begin
        FreeAndNil(RegexObj);
        Exit(False);
      end;
    end;
end;

end.

