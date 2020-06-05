unit uviswaptmessage;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, Buttons;

type

  { TMsgForm }

  TMsgForm = class(TForm)
    ButtonOK: TBitBtn;
    LogoLogin: TImage;
    MsgLabel: TMemo;
    Panel1: TPanel;
    procedure ButtonOKClick;
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure DisplayFileContent(fileName: String);

  private

  public
    procedure ShowHelp; override;
  end;

var
  MsgForm: TMsgForm;

implementation

uses
  base64,
  uWaptMessageRes
  {$IFDEF ENTERPRISE},waptcommon{$ENDIF};

{$R *.lfm}

{ TMsgForm }

procedure TMsgForm.ShowHelp;
begin
  inherited ShowHelp;
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
      MsgLabel.Text := MsgLabel.Text + fileStr + #10#13;
    end;
    CloseFile(msgFile);
  except
    ShowMessage(Format('Could not open or read file %s.', [fileName]));
    Close;
  end;
end;

procedure TMsgForm.FormShow(Sender: TObject);
begin
  MakeFullyVisible();
  Application.BringToFront;

  if Application.HasOption('h', 'help') then
  begin
    ShowHelp();
    Halt;
  end;

  // No flags : print message
  if ParamCount = 1 then
  begin
     MsgLabel.Text := ParamStr(1);
  end
  else if Application.HasOption('b') then // -b flag : message is in base64
  begin
     MsgLabel.Text := DecodeStringBase64(Application.GetOptionValue('b'));
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

procedure TMsgForm.FormCreate(Sender: TObject);
begin
  {$IFDEF ENTERPRISE}
  if FileExists(WaptBaseDir+'\templates\waptself-logo.png') then
     LogoLogin.Picture.LoadFromFile(WaptBaseDir+'\templates\waptself-logo.png')
  else
      LogoLogin.Picture.LoadFromResourceName(HINSTANCE,'LOGOENTERPRISE');
  {$ENDIF}
end;

end.

