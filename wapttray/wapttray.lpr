program wapttray;
{ -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
#    WAPT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WAPT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WAPT.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------
}

{$mode objfpc}{$H+}

uses
  //heaptrc,
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Forms,Interfaces,
  uDMWAPTTray, uwapttray, uwaptres,
  DefaultTranslator,
  Translations, LCLProc;

{$R *.res}

procedure TranslateLCL;
var
  PODirectory, Lang, FallbackLang: String;
  //poFile :TPOFile;

begin
  PODirectory:='C:\codetyphon\typhon\lcl\languages\';
  Lang:='en';
  FallbackLang:='en';
  //LCLGetLanguageIDs(Lang,FallbackLang); // in unit LCLProc

  // ... add here a TranslateUnitResourceStrings call for every po file ...
  Translations.TranslateUnitResourceStrings(
      'LCLStrConsts',
      PODirectory+'lclstrconsts.%s.po',Lang,
      FallbackLang);
  Translations.TranslateUnitResourceStrings(
      'uWaptRes',
      'C:\tranquilit\wapt\languages\wapttray.%s.po',Lang,FallbackLang);

end;

begin
  TranslateLCL;
  RequireDerivedFormResource := True;
  Application.Initialize;
  Application.CreateForm(TDMWaptTray, DMWaptTray);
  Application.Run;
end.

