unit uwizard;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, RTTICtrls,  Forms, Controls,
  Graphics, Dialogs, ExtCtrls, StdCtrls, ComCtrls, EditBtn, Buttons, Menus,
  PopupNotifier, MaskEdit, vte_stringlist, WizardControls;

type

  { TFakeWizardPage }
  TFakeWizardPage = class( TControl, IWizardPage )
    private
    m_dst : IWizardPage;

    public
      constructor Create( dst : IWizardPage ); overload;
      procedure GetPageInfo(var PageInfo: TWizardPageInfo);
  end;


  TWizardStepFuncMode = (wf_enter, wf_validate );
  TWizardStepFunc = function( mode : TWizardStepFuncMode ) : integer of object;
  TWizardStepFuncArray = array of TWizardStepFunc;



  { TWizard }
  TWizard = class(TForm, IWizardPage)
    DescriptionLabel: TLabel;
    Image1: TImage;
    ImageList: TImageList;
    lbl_current_task: TLabel;
    PageControl: TPageControl;
    PopupNotifier: TPopupNotifier;
    WizardProgressBar: TProgressBar;
    TitleLabel: TLabel;
    TopPanel: TPanel;
    WizardButtonPanel: TWizardButtonPanel;
    WizardManager: TWizardManager;

    procedure OnEditClick(Sender: TObject); virtual; final;
    procedure OnEditKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState); virtual; final;
    procedure OnEditEnter(Sender: TObject); virtual; final;
    procedure OnEditExit( Sender : TObject ); virtual; final;

    procedure FormCreate(Sender: TObject); virtual;
    procedure FormDestroy(Sender: TObject); virtual;
    procedure PopupNotifierClose(Sender: TObject; var CloseAction: TCloseAction
      );
    procedure WizardManagerPageHide(Sender: TObject; Page: TWizardPage);
    procedure WizardManagerPageLoad(Sender: TObject; Page: TWizardPage);
    procedure WizardManagerPageShow(Sender: TObject; Page: TWizardPage);


    procedure ShowValidationError( ctrl : TControl; msg : String ); virtual; final;
    procedure SetValidationDescription( description : String ); virtual; final;
    procedure ClearValidationError(); virtual; final;
    procedure ClearValidationDescription(); virtual; final;

    procedure ShowError( msg : String ); virtual; final;

  private
    m_step_funcs : TWizardStepFuncArray;
    m_fake_wizard_page : TFakeWizardPage;

    function validate() : boolean;
    procedure on_button_next(Sender: TObject); virtual; final;
    procedure on_button_finish(Sender : TObject); virtual; final;

  protected
    procedure register_step( title: String; description: String; enable_buttons: TWizardButtons; step_function : TWizardStepFunc );

    procedure register_steps(); virtual; abstract;
    procedure on_wizard_start(); virtual; abstract;
    procedure on_wizard_finish( var mr :TModalResult ); virtual; abstract;

    procedure on_step_show( ts : TTabSheet ); virtual; abstract;
    procedure on_step_taborder( ts : TTabSheet ); virtual abstract;




  public
    // IWizardPage
    procedure GetPageInfo(var PageInfo: TWizardPageInfo); virtual; final;



  end;

implementation

{$R *.lfm}

uses
  character,
  IdCookieManager,
  uwizardutil,
  waptwinutils,
  IniFiles,
  LCLType,
  tiscommon,
  tisutils,
  superobject,
  waptcommon;


{ TFakeWizardPage }

constructor TFakeWizardPage.Create(dst: IWizardPage);  overload;
begin
  inherited Create( nil );
  self.m_dst := dst;
end;

procedure TFakeWizardPage.GetPageInfo(var PageInfo: TWizardPageInfo);
begin
  self.m_dst.GetPageInfo(PageInfo);
end;


{ TWizard }

procedure TWizard.FormCreate(Sender: TObject);
begin
  self.PageControl.ShowTabs := false;

  self.WizardButtonPanel.NextButton.OnClick     := @on_button_next;
  self.WizardButtonPanel.FinishButton.OnClick   := @on_button_finish;
  self.m_fake_wizard_page := TFakeWizardPage.Create( IWizardPage(self) );


  self.WizardProgressBar.Style := pbstNormal;
  self.WizardProgressBar.Min   := 0;
  self.WizardProgressBar.Max   := self.WizardManager.Pages.Count - 1 ;



  self.register_steps();
  self.PageControl.TabIndex    := 0;
  self.WizardManager.PageIndex := 0;

  self.on_wizard_start();
end;

procedure TWizard.FormDestroy(Sender: TObject);
begin
  self.m_fake_wizard_page.Free;
end;

procedure TWizard.PopupNotifierClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  self.ClearValidationError();
end;


procedure TWizard.register_step(title: String; description: String; enable_buttons: TWizardButtons; step_function: TWizardStepFunc);
  procedure visit_and_init( c : TWinControl );
  var
    i : integer;
  begin
    if c is TEdit then
    begin
      TEdit(c).OnClick  := @OnEditClick;
      TEdit(c).OnKeyDown:= @OnEditKeyDown;
      TEdit(c).OnEnter  := @OnEditEnter;
      TEdit(c).OnExit   := @OnEditExit;
    end;

    if c is TDirectoryEdit then
    begin
      TDirectoryEdit(c).OnClick  := @OnEditClick;
      TDirectoryEdit(c).OnKeyDown:= @OnEditKeyDown;
      TDirectoryEdit(c).OnEnter  := @OnEditEnter;
      TDirectoryEdit(c).OnExit   := @OnEditExit;
    end;

    for i := 0 to c.ControlCount -1  do
    begin
      if c.Controls[i] is TWinControl then
        visit_and_init( TWinControl(c.Controls[i]) );
    end;

  end;
const
  DEFAULT_VISIBLE_BUTTONS : TWizardButtons = [ wbPrevious, wbNext, wbFinish, wbCancel ];
var
  p : TWizardPage;
  ts : TTabSheet;
  i : integer;
  c : TControl;
begin
  i := self.WizardManager.Pages.Count;
  self.WizardManager.Pages.Add( inttostr(i), title, self.m_fake_wizard_page );

  p := self.WizardManager.Pages.Items[i];
  p.Caption        := title;
  p.Description    := description;
  p.Control        := self.m_fake_wizard_page;
  P.EnabledButtons := enable_buttons;
  p.VisibleButtons := DEFAULT_VISIBLE_BUTTONS;

  // Set some slots
  ts := self.PageControl.Pages[i];
  visit_and_init( ts );

  // Set step functions
  SetLength( m_step_funcs, i + 1 );
  m_step_funcs[i] := step_function;



end;


procedure TWizard.OnEditKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
begin
  ClearValidationError();
  if key = VK_RETURN then
    self.WizardButtonPanel.NextButton.Click;
end;

procedure TWizard.OnEditClick(Sender: TObject);
begin
  ClearValidationError();
end;

procedure TWizard.OnEditEnter(Sender: TObject);
var
  s : String;
begin
  // Set description label to control.hint value
  if not (Sender is TControl)  then
    exit;
  s := Trim( TControl(Sender).Hint );
  if s = '' then
    exit;
  self.DescriptionLabel.Caption := s;
end;

procedure TWizard.OnEditExit(Sender: TObject);
var
  p : TWizardPage;
begin
  p := self.WizardManager.Pages.Items[ self.WizardManager.PageIndex ];
  self.DescriptionLabel.Caption := p.Description;
end;







procedure TWizard.WizardManagerPageHide(Sender: TObject; Page: TWizardPage);
begin
end;

procedure TWizard.WizardManagerPageLoad(Sender: TObject;  Page: TWizardPage);
begin
end;

procedure TWizard.WizardManagerPageShow(Sender: TObject; Page: TWizardPage);
var
  t : TTabSheet;
  i : integer;
  r : integer;
begin

  ClearValidationError();

  i := self.WizardManager.PageIndex;
  t := TTabSheet(self.PageControl.Page[self.WizardManager.PageIndex]);

  self.WizardProgressBar.Position := i;
  self.PageControl.TabIndex       := Page.Index;
  self.TitleLabel.Caption         := Page.Caption;
  self.DescriptionLabel.Caption   := Page.Description;

  self.on_step_show( t );
  self.on_step_taborder( t );

  t.SelectNext( nil, true, true );



  if Assigned( self.m_step_funcs[i] ) then
    self.m_step_funcs[i]( wf_enter );

end;


function TWizard.validate(): boolean;
var
  t : TTabSheet;
  f : TWizardStepFunc;
  i : integer;
begin
  i := self.PageControl.TabIndex;
  t := TTabSheet(self.PageControl.Page[i]);
  self.lbl_current_task.Parent.RemoveControl( self.lbl_current_task );
  t.InsertControl( self.lbl_current_task );

  self.WizardButtonPanel.Enabled := false;
  Application.ProcessMessages;

  result := true;
  f := self.m_step_funcs[i];
  if Assigned(f) then
    result := f( wf_validate ) = 0;


  self.WizardButtonPanel.Enabled := true;
  Application.ProcessMessages;

end;



procedure TWizard.on_button_next(Sender: TObject);
begin
  if self.validate() = false then
    exit;

  self.WizardManager.DoAction(waNext);
end;

procedure TWizard.on_button_finish(Sender: TObject);
var
  mr : TModalResult;
begin
  self.on_wizard_finish( mr );
  self.ModalResult := mr;
end;


procedure TWizard.ShowValidationError(ctrl: TControl; msg: String);
var
  x : integer;
  y : integer;
begin
  //
  if Assigned(ctrl) then
  begin
    x := ctrl.ClientOrigin.x + 10;
    y := ctrl.ClientOrigin.y + ctrl.Height;
    self.PopupNotifier.Title:= 'Validation error';
    self.PopupNotifier.Text := msg;
    self.PopupNotifier.ShowAtPos( x, y );
    if ctrl is TEdit then
      TEdit(ctrl).SetFocus
    else if ctrl is TDirectoryEdit then
      TDirectoryEdit(ctrl).SetFocus;

    self.lbl_current_task.Font.Color := clRed;
    self.lbl_current_task.Caption := self.lbl_current_task.Caption + ' ... Failed';

    exit;
  end;

  self.lbl_current_task.Font.Color := clRed;
  self.lbl_current_task.Caption :=  msg;

end;
procedure TWizard.SetValidationDescription(description: String);
begin
  self.lbl_current_task.Font.Color := clWindowText;
  self.lbl_current_task.Caption := description;
  Application.ProcessMessages;
end;

procedure TWizard.ClearValidationError();
begin
  self.PopupNotifier.Visible:= false;
  self.lbl_current_task.Font.Color := clWindowText;
  self.lbl_current_task.Caption := '';
end;

procedure TWizard.ClearValidationDescription();
begin
  SetValidationDescription('');
end;

procedure TWizard.ShowError(msg: String);
begin
  self.ShowValidationError( nil, msg );
end;









procedure TWizard.GetPageInfo(var PageInfo: TWizardPageInfo);
var
  p : TWizardPage;
begin
  p := self.WizardManager.Pages[ self.WizardManager.PageIndex ];
  PageInfo.VisibleButtons := p.VisibleButtons;
  PageInfo.EnabledButtons := p.EnabledButtons;
end;




end.

