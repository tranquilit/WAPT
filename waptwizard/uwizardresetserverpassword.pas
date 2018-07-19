unit uwizardresetserverpassword;

{$mode objfpc}{$H+}

interface

uses
  uwizard,
  uwizardresetserverpassword_welcome,
  uwizardresetserverpassword_setpassword,
  uwizardresetserverpassword_restartserver,
  uwizardresetserverpassword_finish,
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs;

type
  TWizardResetServerPassword = class(TWizard)

  private

  public

  end;

var
  WizardResetServerPassword  : TWizardResetServerPassword;
  // 1 Welcome
  // 2 Ensure server
  // 2 Set password
  // 3 Restart services

implementation


{$R *.lfm}

end.

