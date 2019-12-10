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
    CheckBoxWAPT: TCheckBox;
    CheckBoxWUA: TCheckBox;
    CheckBoxHost: TCheckBox;
    ComboBoxUrl: TComboBox;
    ComboBoxCondition: TComboBox;
    ComboBoxSites: TComboBox;
    EditName: TEdit;
    EditValue: TEdit;
    LabPackageType: TLabel;
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
  RegexObj : TRegExpr;
  ComboBoxValue : String;
begin
  if (EditName.Caption='') or (ComboBoxCondition.ItemIndex=-1) or (ComboBoxUrl.Text='') then
    Exit(False)
  else
    begin
      RegexObj:=TRegExpr.Create('^(http|https)://.+');
      if RegexObj.Exec(ComboBoxUrl.Text) then
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
        if (ComboBoxValue=rsHostname ) then
           if (EditValue.Text='') then
              Exit(False);
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

