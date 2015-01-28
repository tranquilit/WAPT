unit uWaptRes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, DefaultTranslator;

resourcestring

  { --- MESSAGES DANS WAPTGET --- }
  rsWinterruptReceived = 'W: interrupt received, killing server…';
  rsStopListening = 'Stop listening to events';
  rsOptRepo = ' -r --repo : URL of dependencies libs';
  rsWaptUpgrade = ' waptupgrade : upgrade wapt-get.exe and database';
  rsWin32exeWrapper = 'Win32 Exe wrapper: %s %s';
  rsWaptGetUpgrade = 'WAPT-GET Upgrade using repository at %s';
  rsDNSserver = 'DNS Server : %s';
  rsDNSdomain = 'DNS Domain : %s';
  rsMainRepoURL = 'Main repo url: %s';
  rsSRV = 'SRV: %s';
  rsCNAME = 'CNAME: %s';
  rsLongtaskError = 'Error launching longtask: %s';
  rsTaskListError = 'Error getting task list: %s';
  rsRunningTask = 'Running task %d: %s, status:%s';
  rsNoRunningTask = 'No running tasks';
  rsPending = 'Pending : ';
  rsErrorCanceling = 'Error cancelling: %s';
  rsCanceledTask = 'Cancelled %s';
  rsErrorLaunchingUpdate = 'Error launching update: %s';
  rsErrorWithMessage = 'Error : %s';
  rsErrorLaunchingUpgrade = 'Error launching upgrade: %s';
  rsCanceled = 'canceled';
  rsUsage = 'Usage: %s -h';
  rsInstallOn = '  install on c:\wapt : --setup -s';
  rsCompletionProgress = '%s : %.0f%% completed';

   { Messages dans wapt-get/waptcommon.pas }
  rsInnoSetupUnavailable = 'Innosetup is unavailable (path : %s), please install it first.';
  rsUndefWaptSrvInIni = 'wapt_server is not defined in your %s ini file';
  rsDlStoppedByUser = 'Download stopped by the user';
  rsCertificateCopyFailure = 'Couldn''t copy certificate %s to %s.';

implementation

end.

