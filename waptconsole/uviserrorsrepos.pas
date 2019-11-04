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
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private

  public

  end;

var
  FormErrorsRepos: TFormErrorsRepos;

implementation

{$R *.lfm}

{ TFormErrorsRepos }

procedure TFormErrorsRepos.FormCreate(Sender: TObject);
begin
  if Screen.PixelsPerInch<>96 then
    GridJSONViewErrors.Header.DefaultHeight:=trunc((GridJSONViewErrors.Header.DefaultHeight*Screen.PixelsPerInch)/96);
end;

procedure TFormErrorsRepos.FormShow(Sender: TObject);
begin
  MakeFullyVisible();
end;

end.

