unit uVisAPropos;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  StdCtrls, DefaultTranslator, Buttons;

type

  { TVisApropos }

  TVisApropos = class(TForm)
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    Image1: TImage;
    LabInfos: TLabel;
    Panel1: TPanel;
    Panel2: TPanel;
    Panel4: TPanel;
    procedure FormCreate(Sender: TObject);
    procedure Image1Click(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisApropos: TVisApropos;

implementation
uses uWaptConsoleRes,tiscommon,waptcommon,LCLIntf,UScaleDPI,uwaptconsole,dmwaptpython;
{$R *.lfm}

{ TVisApropos }

procedure TVisApropos.FormCreate(Sender: TObject);
var
  LicenceFiles:TStringList;
  LicFilename:String;
  Licence: Variant;
begin
  ScaleDPI(Self,96); // 96 is the DPI you designed
  Image1.Picture.LoadFromResourceName(HINSTANCE,'WAPT_PNG',TPortableNetworkGraphic);

  if VisWaptGUI.ActProprietary.Checked then
  begin
    LabInfos.Caption := ApplicationName+' '+GetApplicationVersion+#13#10#13#10'WAPT Enterprise Edition'#13#10'(c) 2012-2017 Tranquil IT Systems.'#13#10#13#10'Configuration:'+AppIniFilename;
    LicenceFiles := FindAllFiles(AppendPathDelim(WaptBaseDir)+'licences','*.lic');
    try
      for LicFilename in LicenceFiles do
      begin
        Licence:=dmwaptpython.DMPython.licencing.WaptLicence(filename := LicFilename);
        LabInfos.Caption := LabInfos.Caption+#13#10+Licence.licence_nr+' count:'+Licence.hosts_count+' end date:'+Licence.valid_until;
      end;
    finally
      LicenceFiles.Free;
    end;
  end
  else
  begin
    Image1.Picture.LoadFromLazarusResource('WAPTCOMMUNITY_PNG');
    LabInfos.Caption := ApplicationName+' '+GetApplicationVersion+#13#10#13#10'WAPT Community Edition'#13#10'(c) 2012-2017 Tranquil IT Systems.'#13#10#13#10'Configuration:'+AppIniFilename;
  end;
end;

procedure TVisApropos.Image1Click(Sender: TObject);
begin
  OpenDocument('http://www.tranquil.it');
end;

end.

