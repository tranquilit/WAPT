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
  RegExpr, uWaptConsoleRes;

{$R *.lfm}

{ TFormEditRule }

procedure TFormEditRule.FormShow(Sender: TObject);
begin
  MakeFullyVisible();
end;

procedure TFormEditRule.ComboBoxConditionChange(Sender: TObject);
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

function TFormEditRule.CanOK(): Boolean;
var
  RegexObj : TRegExpr;
  ComboBoxValue : String;
begin
  if (EditName.Caption='') or (ComboBoxCondition.ItemIndex=-1) or (EditValue.Caption='') or (EditRepoUrl.Caption='') then
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
          if RegexObj.Exec(EditValue.Text) then
          begin
            FreeAndNil(RegexObj);
            Exit(True);
          end
          else
          begin
            FreeAndNil(RegexObj);
            Exit(False);
          end;
        end
        else
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

