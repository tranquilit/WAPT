unit uVisErrorsRepos;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  vte_json;

type

  { TFormErrorsRepos }

  TFormErrorsRepos = class(TForm)
    GridJSONViewErrors: TVirtualJSONInspector;
    procedure FormShow(Sender: TObject);
  private

  public

  end;

var
  FormErrorsRepos: TFormErrorsRepos;

implementation

{$R *.lfm}

{ TFormErrorsRepos }

procedure TFormErrorsRepos.FormShow(Sender: TObject);
begin
  MakeFullyVisible();
end;

end.

