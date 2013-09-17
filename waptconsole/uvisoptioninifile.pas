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
    cbTestRepo: TCheckBox;
    cbPrefix: TCheckBox;
    cbPrivateKey: TCheckBox;
    cbUpload: TCheckBox;
    cbAfterUpload: TCheckBox;
    Edit1: TEdit;
    FileNameEdit1: TFileNameEdit;
    Panel1: TPanel;
    jsonlog: TVirtualJSONInspector;
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure cbTestRepoChange(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
    cbTestRepoChanged:Boolean;
  end;

var
  VisOptionIniFile: TVisOptionIniFile;

implementation
uses dmwaptpython,waptcommon,tisinifiles;

{$R *.lfm}

{ TVisOptionIniFile }


procedure TVisOptionIniFile.cbTestRepoChange(Sender: TObject);
begin
  cbTestRepoChanged := True;
end;

procedure TVisOptionIniFile.FormCreate(Sender: TObject);
begin
  DMPython.PythonEng.ExecString('import waptdevutils');
  cbTestRepo.Checked:= (IniReadString(AppIniFilename,'global','repo_url') = 'http://wapt/wapt-sid');
  cbUpload.Checked:= (IniReadString(AppIniFilename,'global','upload_cmd') <> '');
  cbAfterUpload.Checked:= (IniReadString(AppIniFilename,'global','after_upload') <> '');
end;

procedure TVisOptionIniFile.FormCloseQuery(Sender: TObject;
  var CanClose: boolean);
var
  params:String;
  result:ISuperObject;
  done : Boolean;
  choice : Boolean;
begin
  if ModalResult=mrOk then
  begin
    if cbTestRepoChanged then
    begin
      if cbTestRepo.Checked then
      begin
        params :='';
        choice := True;
        params := params+format('"%s",',['global']);
        params := params+format('"%s",',['repo_url']);
        params := params+format('"%s",',['http://wapt/wapt-sid']);
        result := DMPython.RunJSON(format('waptdevutils.add_remove_option_inifile(mywapt,True,%s)',[params]),jsonlog);

        if cbUpload.Checked then
        begin
          params :='';
          choice := True;
          params := params+format('"%s",',['global']);
          params := params+format('"%s",',['upload_cmd']);
          params := params+format('"%s",',['c:\Program Files\putty\pscp -v -l root %(waptfile)s srvwapt:/var/www/wapt-sid/']);
          result := DMPython.RunJSON(format('waptdevutils.add_remove_option_inifile(mywapt,True,%s)',[params]),jsonlog);
        end;

        if cbAfterUpload.Checked then
        begin
          params :='';
          choice := True;
          params := params+format('"%s",',['global']);
          params := params+format('"%s",',['after_upload']);
          params := params+format('"%s",',['c:\Program Files (x86)\putty\plink -v -l root  -i c:\Users\htouvet\ssl\htouvet-priv.ppk srvwapt python /var/www/wapt/wapt-scanpackages.py /var/www/wapt-sid/']);
          result := DMPython.RunJSON(format('waptdevutils.add_remove_option_inifile(mywapt,True,%s)',[params]),jsonlog);
        end;
      end
      else
      begin
        params :='';
        choice := True;
        params := params+format('"%s",',['global']);
        params := params+format('"%s",',['repo_url']);
        params := params+format('"%s",',['']);
        result := DMPython.RunJSON(format('waptdevutils.add_remove_option_inifile(mywapt,True,%s)',[params]),jsonlog);

        if cbUpload.Checked then
        begin
          params :='';
          choice := True;
          params := params+format('"%s",',['global']);
          params := params+format('"%s",',['upload_cmd']);
          params := params+format('"%s",',['c:\Program Files\putty\pscp -v -l root %(waptfile)s srvwapt:/var/www/%(waptdir)s/']);
          result := DMPython.RunJSON(format('waptdevutils.add_remove_option_inifile(mywapt,True,%s)',[params]),jsonlog);
        end;

        if cbAfterUpload.Checked then
        begin
          params :='';
          choice := True;
          params := params+format('"%s",',['global']);
          params := params+format('"%s",',['after_upload']);
          params := params+format('"%s",',['c:\Program Files (x86)\putty\plink -v -l root  -i c:\Users\htouvet\ssl\htouvet-priv.ppk srvwapt python /var/www/wapt/wapt-scanpackages.py /var/www/%(waptdir)s/']);
          result := DMPython.RunJSON(format('waptdevutils.add_remove_option_inifile(mywapt,True,%s)',[params]),jsonlog);
        end;
      end;
    end;
  end;
end;

end.

