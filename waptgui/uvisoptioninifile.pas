unit uvisOptionIniFile;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  Buttons, StdCtrls, ActnList, EditBtn,fpJson, jsonparser, superobject,vte_json;

type

  { TVisOptionIniFile }

  TVisOptionIniFile = class(TForm)
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    tCheckTestRepo: TCheckBox;
    tCheckPrefix: TCheckBox;
    tCheckPrivateKey: TCheckBox;
    tCheckUpload: TCheckBox;
    tCheckAfterUpload: TCheckBox;
    Edit1: TEdit;
    FileNameEdit1: TFileNameEdit;
    Panel1: TPanel;
    jsonlog: TVirtualJSONInspector;
    procedure FormCreate(Sender: TObject);
    procedure tCheckTestRepoChange(Sender: TObject);
    procedure FileNameEdit1Change(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisOptionIniFile: TVisOptionIniFile;

implementation
uses dmwaptpython;

{$R *.lfm}

{ TVisOptionIniFile }


procedure TVisOptionIniFile.tCheckTestRepoChange(Sender: TObject);
var
  params:String;
  result:ISuperObject;
  done : Boolean;
  choice : Boolean;
begin
  if tCheckTestRepo.Checked then
  begin
    params :='';
    choice := True;
    params := params+format('"%s",',['global']);
    params := params+format('"%s",',['repo_url']);
    params := params+format('"%s",',['http://wapt/wapt-sid']);
    result := DMPython.RunJSON(format('waptdevutils.add_remove_option_inifile(mywapt,True,%s)',[params]),jsonlog);
  end
  else
  begin
    params :='';
    choice := True;
    params := params+format('"%s",',['global']);
    params := params+format('"%s",',['repo_url']);
    params := params+format('"%s",',['']);
    result := DMPython.RunJSON(format('waptdevutils.add_remove_option_inifile(mywapt,True,%s)',[params]),jsonlog);
  end;

end;

procedure TVisOptionIniFile.FormCreate(Sender: TObject);
begin
   DMPython.PythonEng.ExecString('import waptdevutils');
end;

procedure TVisOptionIniFile.FileNameEdit1Change(Sender: TObject);
begin

end;

end.

