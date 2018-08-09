unit uwizardresetserverpassword;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardresetserverpassword_data,
  uwizardresetserverpassword_welcome,
  uwizardresetserverpassword_setpassword,
  uwizardresetserverpassword_restartserver,
  uwizardresetserverpassword_finish,
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs;

type

  { TWizardResetServerPassword }

  TWizardResetServerPassword = class(TWizard)

  private
    m_data : TWizardResetServerPasswordData;
  public
    function data() : Pointer; override; final;
  end;

var
  WizardResetServerPassword  : TWizardResetServerPassword;
  // 1 Welcome
  // 2 Ensure server
  // 2 Set password
  // 3 Restart services

implementation


{$R *.lfm}

{ TWizardResetServerPassword }

function TWizardResetServerPassword.data(): Pointer;
begin
  exit( @m_data );


end;

end.

