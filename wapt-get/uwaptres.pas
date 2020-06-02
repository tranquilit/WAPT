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
  rsWaptgetHelp = ' waptupgrade : upgrade wapt-get.exe and database'#13#10+
                  ' tasks : check if some tasks are running or pending in queue'#13#10+
                  ' dnsdebug : display some informations about DNS configuration.'#13#10
                 ;
  rsWin32exeWrapper = 'Win32 Exe wrapper: %s %s';
  rsBuildWaptAgent = 'Building customized waptagent.exe installer';
  rsBuildWaptUpgradePackage = 'Building waptupgrade package';
  rsUploadWaptAgent = 'Uploading customized waptagent.exe installer';
  rsWaptGetUpgrade = 'WAPT-GET Upgrade using repository at %s';
  rsDNSserver = 'DNS Server : %s';
  rsDNSdomain = 'DNS Domain : %s';
  rsMainRepoURL = 'Main repo url: %s';
  rsSRVwapt = 'wapt SRV: %s';
  rsSRVwaptserver = 'waptserver SRV: %s';
  rsCNAME = 'CNAME: %s';
  rsLongtaskError = 'Error launching longtask: %s';
  rsTaskListError = 'Error getting task list: %s';
  rsRunningTask = 'Running task %d: %s, status:%s';
  rsNoRunningTask = 'No running tasks';
  rsPending = 'Pending : ';
  rsErrorCanceling = 'Error cancelling: %s';
  rsCanceledTask = 'Cancelled %s';
  rsErrorLaunchingUpdate = 'Error launching update: %s';
  rsErrorLaunchingRegister = 'Error launching register: %s';
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

  { licence management }
  rsWAPTLicenceExpirationWarning = 'Licence will expire in %d days, keep in mind to renew them.';
  rsWAPTLicenceExpired = 'Licence nr %s has expired.';
  rsWAPTLicenceDuplicated = 'Duplicated Licence nr %s';
  rsWAPTNoValidLicenceFound = 'No valid licence found in %s, switching to Community features only';

  { waptservice states }
  rsWssStopped = 'WAPTService stopped';
  rsWssStarting  = 'WAPTService is starting';
  rsWssRunning =  'WAPTService is running';
  rsWssStopping = 'WAPTService is stopping';

  rsQueryApplyUpdates = 'Some of your changes are not yet saved. Do you want to save your changes ?';



implementation

end.

