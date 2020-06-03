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
    procedure ButtonOKClick();
    procedure FormShow();
    procedure DisplayFileContent(fileName: String);
    procedure ShowHelp;
  private

  public

  end;

var
  MsgForm: TMsgForm;

implementation

{$R *.lfm}

{ TMsgForm }

procedure TMsgForm.ShowHelp;
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

procedure TMsgForm.FormShow;
begin
  if Application.HasOption('h', 'help') then
  begin
    ShowHelp();
    Halt;
  end;

  // No flags : print message
  if ParamCount = 1 then
  begin
     MsgLabel.Caption := ParamStr(1);
  end
  else if Application.HasOption('f') then // -f flag : message is the file content
  begin
     DisplayFileContent(Application.GetOptionValue('f'));
  end
  else
  begin
    ShowHelp();
    Close;
  end;
end;

procedure TMsgForm.ButtonOKClick;
begin
  Close;
end;

end.

