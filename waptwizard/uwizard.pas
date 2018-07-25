unit uwizard;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, RTTICtrls, Forms, Controls, Graphics, Dialogs,
  ExtCtrls, StdCtrls, ComCtrls, EditBtn, Buttons, Menus, PopupNotifier,
  MaskEdit, WizardControls;

type

  TWizardStepFuncMode = (wf_enter, wf_validate );
  TWizardStepFunc = function( mode : TWizardStepFuncMode ) : integer of object;
  TWizardStepFuncArray = array of TWizardStepFunc;



  { TWizard }
  TWizard = class(TForm )
    DescriptionLabel: TLabel;
    img_logo: TImage;
    ImageList: TImageList;
    lbl_current_task: TLabel;
    panel_center: TPanel;
    PopupNotifier: TPopupNotifier;
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
    procedure panel_centerClick(Sender: TObject);
    procedure PopupNotifierClose(Sender: TObject; var CloseAction: TCloseAction );
    procedure WizardManagerPageHide(Sender: TObject; Page: TWizardPage);
    procedure WizardManagerPageLoad(Sender: TObject; Page: TWizardPage);
    procedure WizardManagerPageShow(Sender: TObject; Page: TWizardPage); virtual;


    procedure SetValidationDescription( description : String ); virtual; final;
    procedure ClearValidationError(); virtual; final;
    procedure ClearValidationDescription(); virtual; final;
    procedure WizardManagerPageStateChange(Sender: TObject; Page: TWizardPage);

  private
    m_wizard_panel_proc_next_onclick : TNotifyEvent;
    procedure on_button_next_click( sender : TObject );
    procedure on_button_finish_click( sender : TObject );
    procedure on_button_cancel_click( sender : TObject );
    procedure set_buttons_enable( enable : Boolean );
    procedure _click_next_async( data : PtrInt );
    procedure _setfocus_async( data : PtrInt );



  protected

  public

    function data() : Pointer; virtual; abstract;

    function  show_info(    const msg : String; buttons : TMsgDlgButtons ) : TModalResult; virtual; final;
    function  show_question(const msg : String; buttons : TMsgDlgButtons ) : TModalResult; virtual; final;
    function  show_warning( const msg : String; buttons : TMsgDlgButtons ) : TModalResult; virtual; final;
    function  show_error(   const msg : String; buttons : TMsgDlgButtons ) : TModalResult; virtual; final;
    procedure show_error(   const msg : String ); virtual overload; final;
    procedure show_validation_error( ctrl : TControl; msg : String ); virtual; final;



    procedure click_next_async();
    procedure setFocus_async( wc : TWinControl );


    procedure launch_console();

  end;

implementation

{$R *.lfm}

uses
  dmwaptpython,
  uwizardstepframe,
  character,
  IdCookieManager,
  uwizardutil,
  waptwinutils,
  IniFiles,
  LCLType,
  tiscommon,
  tisutils,
  waptcommon;


function current_step( w : TWizard ) : TWizardStepFrame;
var
  r : integer;
begin
  r := w.WizardManager.PageIndex;

  if r < 0 then
    exit( nil );

  result := TWizardStepFrame(w.WizardManager.Pages[r].Control);
end;

function current_page( w : TWizard ) : TWizardPage;
var
  r : integer;
begin
  r := w.WizardManager.PageIndex;

  if r < 0 then
    exit( nil );

  result := w.WizardManager.Pages[r];
end;

{ TWizard }
procedure TWizard.FormCreate(Sender: TObject);
begin


  // Trick Next
  m_wizard_panel_proc_next_onclick := self.WizardButtonPanel.NextButton.OnClick;
  self.WizardButtonPanel.NextButton.OnClick := @on_button_next_click;

  self.WizardButtonPanel.FinishButton.OnClick := @on_button_finish_click;
  self.WizardButtonPanel.CancelButton.OnClick := @on_button_cancel_click;

  //
  self.panel_center.Caption := '';
  self.lbl_current_task.Caption := '';

  if self.WizardManager.Pages.Count > 0 then
    self.WizardManager.PageIndex := 0;



end;

procedure TWizard.FormDestroy(Sender: TObject);
begin
end;

procedure TWizard.panel_centerClick(Sender: TObject);
begin
  self.ClearValidationError();
end;

procedure TWizard.PopupNotifierClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  self.ClearValidationError();
end;

function TWizard.show_info(const msg: String; buttons: TMsgDlgButtons ): TModalResult;
begin
  result := MessageDlg( self.Caption, msg, mtInformation, buttons, 0 );
end;

function TWizard.show_question(const msg: String; buttons: TMsgDlgButtons ): TModalResult;
begin
  result := MessageDlg( self.Caption, msg, mtConfirmation, buttons, 0 );
end;


function TWizard.show_warning(const msg: String; buttons: TMsgDlgButtons ): TModalResult;
begin
  result := MessageDlg( self.Caption, msg, mtWarning, buttons, 0 );
end;

function TWizard.show_error(const msg: String; buttons: TMsgDlgButtons ): TModalResult;
begin
  result := MessageDlg( self.Caption, msg, mtError, buttons, 0 );
end;

procedure TWizard.show_error(const msg: String);
begin
  self.show_error( msg, [mbOK] );
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
var
  step : TWizardStepFrame;
begin
  step := current_step(self);

  if not Assigned(step) then
    exit;

  step.wizard_hide();
  self.ClearValidationDescription();

end;

procedure TWizard.WizardManagerPageLoad(Sender: TObject;  Page: TWizardPage);
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

    if c is TCheckBox then
      TCheckBox(c).OnClick := @OnEditClick;

    if c is TRadioGroup then
      TRadioGroup(c).OnClick:= @OnEditClick;

    if c is TDirectoryEdit then
    begin
      TDirectoryEdit(c).OnClick  := @OnEditClick;
      TDirectoryEdit(c).OnKeyDown:= @OnEditKeyDown;
      TDirectoryEdit(c).OnEnter  := @OnEditEnter;
      TDirectoryEdit(c).OnExit   := @OnEditExit;
    end;

    if c is TFileNameEdit then
    begin
      TFileNameEdit(c).OnClick  := @OnEditClick;
      TFileNameEdit(c).OnKeyDown:= @OnEditKeyDown;
      TFileNameEdit(c).OnEnter  := @OnEditEnter;
      TFileNameEdit(c).OnExit   := @OnEditExit;
    end;

    for i := 0 to c.ControlCount -1  do
    begin
      if c.Controls[i] is TWinControl then
        visit_and_init( TWinControl(c.Controls[i]) );
    end;

  end;

var
  step : TWizardStepFrame;
begin
  step := current_step(self);

  if not Assigned(step) then
    exit;

  step.clear();
  step.wizard_load(self );
  visit_and_init( step );

end;

procedure TWizard.WizardManagerPageShow(Sender: TObject; Page: TWizardPage);
var
  step : TWizardStepFrame;
  r    : Real;
begin
  step := current_step(self);

  if not Assigned(step) then
    exit;


  // Center
  step.Align:= alNone;
  r := Real(self.panel_center.Height) * 0.5 - Real(step.Height) * 0.5;
  step.Top := round(r);

  r := Real(self.panel_center.Width) * 0.5 - Real(step.Width) * 0.5;
  step.Left := round(r);

  self.TitleLabel.Caption := Page.Caption;
  self.DescriptionLabel.Caption := Page.Description;

  self.ClearValidationDescription();
  self.ClearValidationError();

  step.wizard_show();

end;

procedure TWizard.WizardManagerPageStateChange(Sender: TObject; Page: TWizardPage);
begin
end;

procedure TWizard.on_button_next_click(sender: TObject );
var
  step : TWizardStepFrame;
  i : integer;
  bCanNext : boolean;
begin
  step := current_step( self );
  if not assigned(step) then
    exit;

  bCanNext := true;;

  set_buttons_enable( false );
  try
    step.wizard_next( bCanNext );
  except on Ex : Exception do
    self.show_validation_error( nil, ex.Message );
  end;
  set_buttons_enable( true );

  if not bCanNext then
    exit;

  self.ClearValidationError();
  self.ClearValidationDescription();
  self.m_wizard_panel_proc_next_onclick( sender );

end;
procedure TWizard.on_button_finish_click(sender: TObject);
var
  b : boolean;
begin
  b := true;
  current_step(self).wizard_finish(b);
  if b then
    Close;
end;

procedure TWizard.on_button_cancel_click(sender: TObject);
var
  b : boolean;
begin
  b := true;
  current_step(self).wizard_cancel(b);
  self.WizardManager.DoAction(waCancel);
  if b then
    Close;
end;

procedure TWizard.set_buttons_enable( enable : Boolean);
begin
  self.WizardButtonPanel.Enabled := enable;
  Application.ProcessMessages;
end;

procedure TWizard._click_next_async(data: PtrInt);
begin
  self.WizardButtonPanel.NextButton.Click;
end;

procedure TWizard._setfocus_async(data: PtrInt);
begin
  if data = 0 then
    exit;

  // todo if
  TWinControl(data).SetFocus;
end;


procedure TWizard.click_next_async();
begin
  Application.QueueAsyncCall( @_click_next_async, 0 );

end;

procedure TWizard.setFocus_async(wc: TWinControl);
begin
  Application.QueueAsyncCall( @_setfocus_async, PtrInt(wc) );
end;

procedure TWizard.launch_console();
var
  r : integer;
  s : String;
  cmd : String;
begin
  cmd := 'waptconsole.exe';

  s := '';
  r := wapt_console_install_path(s);
  if r = 0 then
    cmd := IncludeTrailingBackslash(s) + cmd;

  r := process_launch( cmd , s);
  if r <> 0 then
    self.show_error( 'An error has occured while launching the console');
end;





procedure TWizard.show_validation_error(ctrl: TControl; msg: String);
var
  x : integer;
  y : integer;
  s: String;
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
      TDirectoryEdit(ctrl).SetFocus
    else if ctrl is TRadioGroup then
      TRadioGroup(ctrl).SetFocus;


    self.lbl_current_task.Font.Color := clRed;
    s := Trim(self.lbl_current_task.Caption);
    if Length(s) > 0 then
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
  self.PopupNotifier.Visible := false;
end;




end.

