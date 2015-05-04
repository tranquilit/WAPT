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
  rsUsage4 = ' --force : install waptagent.exe even if version doesn''t match';
  rsUsage5 = ' --minversion=1.2.3 : install waptagent.exe even if installed version is less than that';
  rsUsage6 = ' --repo_url=http://wapt/wapt : location of repo where to lookup waptdeploy.version and to get waptagent.exe';
  rsUsage7 = ' --waptsetupurl=http://wapt/wapt/waptagent.exe : location wher to download setup exe. (default=<repo_url>/waptagent.exe';
  rsUsage8 = ' --tasks=autorunTray,installService,installredist2008,autoUpgradePolicy  : if given, pass this arguments to the /TASKS options of the waptagent installer. Default = installService,installredist2008,autoUpgradePolicy';
  rsUsage9 = ' --hash=<sha256hash> : check that downloaded waptagent.exe setup sha256 hash match this parameter.';
  rsInstall = 'Install ...';
  rsInstallOK = 'Install OK : %s';
  rsVersionError = 'Got a waptsetup version older than required version';
  rsCleanup = 'Cleanup...';
  rsNothingToDo = 'Nothing to do';

implementation

end.

