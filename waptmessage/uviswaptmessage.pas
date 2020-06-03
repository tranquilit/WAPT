unit uviswaptmessage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  uWaptMessageRes;

type

  { TMsgForm }

  TMsgForm = class(TForm)
    Label1: TLabel;
    procedure FormShow(Sender: TObject);
    procedure DisplayFileContent(fileName: String);
  private

  public

  end;

var
  MsgForm: TMsgForm;

implementation

{$R *.lfm}

{ TMsgForm }

procedure WriteHelp;
begin
  WriteLn(rsHelp);
  Halt();
end;

procedure TMsgForm.DisplayFileContent(fileName: String);
var
  msgFile: TextFile;
  fileContent: String;
begin
  try
    AssignFile(msgFile, fileName);
    Reset(msgFile);
    Read(msgFile, fileContent);
    Label1.Caption := fileContent;
  except
    writeln(stderr,'Could not find, open or read file');
    Halt(1);
  end;
end;

procedure TMsgForm.FormShow(Sender: TObject);
begin
  if Application.HasOption('h', 'help') then
  begin
    WriteHelp();
    Halt();
  end;

  // No flags : print message
  if ParamCount = 1 then
  begin
     Label1.Caption := ParamStr(0);
  end;

  // -f flag : message is file content
  if Application.HasOption('f') then
    DisplayFileContent(Application.GetOptionValue('f'));
end;

end.

