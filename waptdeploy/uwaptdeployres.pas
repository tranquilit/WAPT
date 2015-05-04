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
  rsUsage2 = '  Download waptagent.exe from WAPT repository and launch it if local version is obsolete (< %s or < parameter 1 or < --minversion parameter)';
  rsUsage3 = ' --force : install waptagent.exe even if version doesn''t match';
  rsUsage4 = ' --minversion=1.2.3 : install waptagent.exe even if installed version is less than that';
  rsUsage5 = ' --repo_url=http://wapt/wapt : location of repo where to lookup waptdeploy.version and to get waptagent.exe';
  rsUsage6 = ' --waptsetupurl=http://wapt/wapt/waptagent.exe : location wher to download setup exe. (default=<repo_url>/waptagent.exe';
  rsUsage7 = ' --tasks=autorunTray,installService,installredist2008,autoUpgradePolicy  : if given, pass this arguments to the /TASKS options of the waptagent installer. Default = installService,installredist2008,autoUpgradePolicy';
  rsUsage8 = ' --hash=<sha256hash> : check that downloaded waptagent.exe setup sha256 hash match this parameter.';
  rsInstall = 'Install ...';
  rsInstallOK = 'Install OK : %s';
  rsInstallError = 'Install Error : %s';
  rsVersionError = 'Got a waptsetup version older than required version';
  rsHashError = 'Error found in downloaded setup file: HASH mismatch. File is perhaps corrupted.';
  rsCleanup = 'Cleanup...';
  rsNothingToDo = 'Nothing to do';

implementation

end.

