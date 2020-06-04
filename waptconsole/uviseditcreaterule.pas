unit uviseditcreaterule;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons, ActnList;

type

  { TFormEditRule }

  TFormEditRule = class(TForm)
    BitBtnOk: TBitBtn;
    BitBtnCancel: TBitBtn;
    CheckBoxNoFallback: TCheckBox;
    CheckBoxNegation: TCheckBox;
    CheckBoxWAPT: TCheckBox;
    CheckBoxWUA: TCheckBox;
    CheckBoxHost: TCheckBox;
    ComboBoxUrl: TComboBox;
    ComboBoxCondition: TComboBox;
    ComboBoxSites: TComboBox;
    EditName: TEdit;
    EditValue: TEdit;
    LabPackageType: TLabel;
    LabOtherSettings: TLabel;
    LabValue: TLabel;
    LabName: TLabel;
    LabCondition: TLabel;
    LabRepoURL: TLabel;
    procedure ComboBoxConditionChange(Sender: TObject);
    procedure EditNameChange(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormKeyPress(Sender: TObject; var Key: char);
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
  if (ComboBoxCondition.ItemIndex<>-1) then
  begin
    EditValue.Text:='';
    if (ComboBoxCondition.Items[ComboBoxCondition.ItemIndex]=rsSite) then
    begin
      if (ComboBoxSites.Items.Count=0) then
      begin
        Sites:=WAPTServerJsonGet('api/v3/get_ad_sites',[])['result'];
        if Assigned(Sites) then
          for Site in Sites do
              ComboBoxSites.Items.Add(Site.AsString{%H-});
      end;
      ComboBoxSites.Visible:=True;
      ComboBoxSites.Enabled:=True;
      EditValue.Visible:=False;
      EditValue.Enabled:=False;
    end
    else
    begin
      ComboBoxSites.Visible:=False;
      ComboBoxSites.Enabled:=False;
      EditValue.Visible:=True;
      EditValue.Enabled:=True;
    end;
  end;
  BitBtnOk.Enabled:=CanOk();
end;

procedure TFormEditRule.EditNameChange(Sender: TObject);
begin
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

procedure TFormEditRule.FormKeyPress(Sender: TObject; var Key: char);
begin
  if Key=#27 then
    Close;
end;

function TFormEditRule.CanOK(): Boolean;
var
  RegexObj1,RegexObj2 : TRegExpr;
  ComboBoxValue : String;
begin
  if (EditName.Caption='') or (ComboBoxCondition.ItemIndex=-1) or (ComboBoxUrl.Text='') then
    Exit(False)
  else
    begin
      RegexObj1:=TRegExpr.Create('^(http|https)://.+');
      if RegexObj1.Exec(ComboBoxUrl.Text) then
      begin
        FreeAndNil(RegexObj1);
        ComboBoxValue:=ComboBoxCondition.Items[ComboBoxCondition.ItemIndex];
        if (ComboBoxValue=rsAgentIP) or (ComboBoxValue=rsPublicIP) then
        begin
          RegexObj1:=TRegExpr.Create('^((\d){1,3}\.){3}(\d){1,3}\/(\d){1,2}$');
          RegexObj2:=TRegExpr.Create('^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(\/((1(1[0-9]|2[0-8]))|([0-9][0-9])|([0-9])))?$');
          if (RegexObj1.Exec(EditValue.Text) or RegexObj2.Exec(EditValue.Text)) and (EditValue.Text<>'') then
          begin
            FreeAndNil(RegexObj1);
            FreeAndNil(RegexObj2);
            Exit(True);
          end
          else
          begin
            FreeAndNil(RegexObj1);
            FreeAndNil(RegexObj2);
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
        if (ComboBoxValue=rsHostname ) then
           if (EditValue.Text='') then
              Exit(False);
        Exit(True);
      end
      else
      begin
        FreeAndNil(RegexObj1);
        Exit(False);
      end;
    end;
end;

end.

