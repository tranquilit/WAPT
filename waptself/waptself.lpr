program WaptSelf;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, uviswaptself, uVisLogin,
  LCLTranslator, waptcommon, sysutils, IniFiles,uDMWaptSelf;

var
  ini: TIniFile;
begin
  {$ifdef ENTERPRISE }
  {$R waptself.res}
  {$endif}
  //Create ini in AppData/Local/waptself and read language
  ini:=TIniFile.Create(AppIniFilename);
  if (ini.ReadString('global','language','')<>'') then
    SetDefaultLang(ini.ReadString('global','language',''))
  else
    begin
      ini.WriteString('global','language','');
      ini.UpdateFile;
    end;

  FreeAndNil(ini);
  Application.Scaled:=True;
  RequireDerivedFormResource:=True;
  Application.ShowMainForm:=false;
  Application.Initialize;
  Application.CreateForm(TDMWaptSelf,DMWaptSelf);
  Application.CreateForm(TVisWaptSelf, VisWaptSelf);
  VisWaptSelf.Visible:=false;
  Application.Run;
end.

