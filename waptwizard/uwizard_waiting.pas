unit uwizard_waiting;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ComCtrls,
  StdCtrls, ExtCtrls;

type

  { TWizard_Waiting }

  TWizard_Waiting = class(TForm)
    Label1: TLabel;
    panel: TPanel;
    progress: TProgressBar;
  private

  public

  end;

implementation

{$R *.lfm}

end.

