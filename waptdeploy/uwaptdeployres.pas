unit uWaptDeployRes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

resourcestring

  { --- MESSAGES DANS WAPTDEPLOY --- }
  rsWininetGetFlagsError = 'Internal error in SetToIgnoreCerticateErrors when trying to get wininet flags. %s';
  rsWininetSetFlagsError = 'Internal error in SetToIgnoreCerticateErrors when trying to set wininet INTERNET_OPTION_SECURITY_FLAGS flag . %s';
  rsUnknownError = 'Unknown error in SetToIgnoreCerticateErrors. %s';

  rsUsage1 = 'Usage : waptdeploy.exe [min_wapt_version]';
  rsUsage2 = '  Download waptagent.exe from WAPT repository and launch it if local version is obsolete (< %s or < parameter 1)';
  rsUsage3 = '  If no argument is given, looks for http://%s/waptdeploy.version file. This file should contain 2 lines. One for version, and another for download url';
  rsUsage4 = '  If --force is given, install waptagent.exe even if version doesn''t match';
  rsUsage5 = '  If --tasks=useWaptServer,autorunTray is given, pass this arguments to the /MERGETASKS options of the waptagent installer';
  rsUsage6 = '  If --hash=<sha256hash> is given, check that downloaded waptagent.exe setup sha256 hash match this parameter.';
  rsInstall = 'Install ...';
  rsInstallOK = 'Install OK : %s';
  rsVersionError = 'Got a waptsetup version older than required version';
  rsCleanup = 'Cleanup...';
  rsNothingToDo = 'Nothing to do';

implementation

end.

