unit uviswaptmessage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons, uWaptMessageRes;

type

  { TMsgForm }

  TMsgForm = class(TForm)
    ButtonOK: TBitBtn;
    LogoLogin: TImage;
    MsgLabel: TLabel;
    Panel1: TPanel;
    procedure ButtonOKClick(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure DisplayFileContent(fileName: String);
  private
    procedure WriteHelp;

  public

  end;

var
  MsgForm: TMsgForm;

implementation

{$R *.lfm}

{ TMsgForm }

procedure TMsgForm.WriteHelp;
begin
  ShowMessage(rsHelp);
end;

procedure TMsgForm.DisplayFileContent(fileName: String);
var
  msgFile: TextFile;
  fileStr: String;
begin
  if not FileExists(fileName) then
  begin
    ShowMessage(Format('File %s could not be found.', [fileName]));
    Halt;
  end;

  try
    AssignFile(msgFile, fileName);
    Reset(msgFile);
    while not eof(msgFile) do
    begin
      ReadLn(msgFile, fileStr);
      MsgLabel.Caption := MsgLabel.Caption + fileStr + #10#13;
    end;
    CloseFile(msgFile);
  except
    ShowMessage(Format('Could not open or read file %s.', [fileName]));
    Close;
  end;
end;

procedure TMsgForm.FormShow(Sender: TObject);
begin
  if Application.HasOption('h', 'help') then
  begin
    WriteHelp();
    Halt;
  end;

  // No flags : print message
  if ParamCount = 1 then
  begin
     MsgLabel.Caption := ParamStr(1);
  end;

  // -f flag : message is the file content
  if Application.HasOption('f') then
    DisplayFileContent(Application.GetOptionValue('f'));
end;

procedure TMsgForm.ButtonOKClick(Sender: TObject);
begin
  Close;
end;

end.

