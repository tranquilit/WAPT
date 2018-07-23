unit uwizardconfigconsole_package_use_existing_key;

{$mode objfpc}{$H+}

interface

uses
    uwizardstepframe,
  Classes, SysUtils, FileUtil, Forms, Controls, StdCtrls, EditBtn;

type

  { TTWizardConfigConsole_PackageUseExistingKey }

  TTWizardConfigConsole_PackageUseExistingKey = class(TWizardStepFrame)
    cb_show_password: TCheckBox;
    ed_key: TFileNameEdit;
    ed_package_prefix: TEdit;
    ed_password: TEdit;
    gb_package: TGroupBox;
    gb_package_signing: TGroupBox;
    lbl_package_prefix: TLabel;
    lbl_password: TLabel;
    lbl_select_key: TLabel;
  private

  public

    procedure wizard_next(var bCanNext: boolean); override; final;
  end;

implementation

uses
  uwizardutil,
  uwizardvalidattion,
  IniFiles,
  uwizardconfigconsole_data;


{$R *.lfm}

{ TTWizardConfigConsole_PackageUseExistingKey }

procedure TTWizardConfigConsole_PackageUseExistingKey.wizard_next( var bCanNext: boolean);
var
  ini : TIniFile;
  data : PWizardConfigConsoleData;
begin

  bCanNext := false;
  data := m_wizard.data();






end;

end.

