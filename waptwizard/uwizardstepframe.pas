unit uwizardstepframe;

{$mode objfpc}{$H+}

interface

uses
  WizardControls,
  superobject,
  uwizard,
  Classes, SysUtils, FileUtil, Forms, Controls;

type

  { TWizardStepFrame }

  TWizardStepFrame = class( TFrame, IWizardPage )

  protected
    m_wizard      : TWizard;
    m_show_count  : integer;
    m_data        : ISuperObject;


  public
    constructor Create( AOwner : TComponent ); override;


    procedure wizard_load( w : TWizard; data : ISuperObject ); virtual;
    procedure wizard_show(); virtual;
    procedure wizard_hide(); virtual;
    function  wizard_validate() : integer; virtual; abstract;
    procedure wizard_finish(); virtual;
    procedure clear(); virtual;
    procedure GetPageInfo(var PageInfo: TWizardPageInfo); virtual;

  end;

{

  // TWizardStepFrame
  function wizard_validate() : integer;  override; final;


  // TWizardStepFrame
  procedure wizard_show( w : TWizard; data : ISuperObject ); override; final;
  procedure wizard_hide(); override; final;
  procedure wizard_load( w : TWizard; data : ISuperObject);  override; final;
  function wizard_validate() : integer;  override; final;
  procedure clear();  override; final;
  procedure GetPageInfo(var PageInfo: TWizardPageInfo);  override; final;
}

implementation



{$R *.lfm}

{ TWizardStepFrame }

constructor TWizardStepFrame.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  m_show_count := 0;
  m_data := nil;
  m_wizard := nil;
end;

procedure TWizardStepFrame.wizard_load(w: TWizard; data: ISuperObject);
begin
  m_wizard := w;
  m_data := data;
end;

procedure TWizardStepFrame.wizard_show();
begin
  self.m_show_count := self.m_show_count + 1;
end;

procedure TWizardStepFrame.wizard_hide();
begin
end;

procedure TWizardStepFrame.wizard_finish();
begin
end;

procedure TWizardStepFrame.clear();
begin
end;

procedure TWizardStepFrame.GetPageInfo(var PageInfo: TWizardPageInfo);
begin
end;

end.

