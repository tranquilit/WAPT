unit uWaptConsoleRes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, DefaultTranslator;

resourcestring

  { --- MESSAGES DANS LA CONSOLE WAPT --- }
  { Messages dans uwaptconsole.pas }
  rsLoadPackages = 'Loading Packages index';
  rsLoadInventory = 'Loading hosts inventory';
  rsLoadSettings = 'Loading application settings';

  rsFatalError = 'Failed to retrieve task.';
  rsInstalling = 'Installing %s...';
  rsDefineWaptdevPath = 'Please select a directory on your package development host before editing a package bundle.';

  rsPublicKeyGenSuccess = 'Public certificate %s has been successfully created.';
  rsKeyPairGenSuccess = 'Private key %s and public certificate %s have been successfully created.';
  rsPublicKeyGenFailure = 'The generation of the public certificate has failed.';
  rsPublicKeyGenError = 'Error during key generation : %s';

  rsWriteCertOnLocalMachine = 'Do you want to copy this certificate to ssl Authorized Package Certificate store (%s) ?';

  rsCreationInProgress = 'Build in progress.';
  rsProgressTitle = 'Started uploading to WAPT server...';  // TODO more meaningful var name
  rsWaptSetupUploadSuccess = 'WAPT agent and upgrade package successfully created and uploaded to the main repository'#13#10'Don''t forget to change the hash of waptagent.exe in your GPO';
  rsWaptUploadError = 'Error while uploading WAPT agent to the repository : %s';
  rsWaptSetupError = 'Error while creating agent : %s';

  rsWaptUpgradePackageBuilt = 'WAPT Upgrade package built and uploaded successfully';
  rsWaptUpgradePackageBuildError = 'Unable to create WAPT Upgrade package';

  rsForcedUninstallPackages = 'Selection of packages to force-remove from the hosts';
  rsDependencies = 'Selection of packages to add to the hosts as dependencies';
  rsNbModifiedHosts = '%s hosts affected.';
  rsTaskCanceled = 'Task canceled.';
  rsFailedToCancel = 'Could not cancel : %s.';

  rsNoReachableIP = 'None IP reachable for this host. Check firewall, routes and remote service status';

  rsIncorrectPassword = 'Incorrect password.';
  rsPasswordChangeSuccess = 'Password successfully updated !';
  rsPasswordChangeError = 'Error : %s';

  rsWaptServerError = 'Error on WAPT server:'#13#10'%s';
  rsWaptServerOldVersion = 'Warning, the version of the server is too old.'#13#10'Current server version: %s'#13#10'Required server version: %s';
  rsUnknownVersion = 'Unknown version';

  rsWaptAgentOldVersion = 'Warning, the version of the waptagent.exe installer is too old.'#13#10'Current waptagent.exe version: %s'#13#10'waptsetup-tis.exe version: %s';
  rsWaptAgentNotPresent = 'Warning, waptagent.exe installer is not present on server, please build waptagent.exe installer for the deployment of Wapt on client hosts.';

  rsWaptAgentUploadSuccess = 'Successfully uploaded WAPT agent !';
  rsWaptAgentUploadError = 'Error while uploading WAPT agent : %s';
  rsWaptAgentSetupSuccess = 'waptagent.exe successfully built : %s';
  rsWaptAgentSetupError = 'Error while creating waptagent.exe: %s';

  rsConfirmRmOnePackage = 'Are you sure you want to remove this package from the server ?';
  rsConfirmRmMultiplePackages = 'Are you sure you want to remove %d selected packages from the server ?';
  rsConfirmRmPackageCaption = 'Confirm removal';
  rsDeletionInProgress = 'Removing packages...';
  rsDeletingElement = 'Removing %s';
  rsUpdatingPackageList = 'Updating package list';
  rsDisplaying = 'Displaying';
  rsConfirmDeletion = 'Confirm removal';  // Duplicate of rsConfirmRmPackageCaption

  rsHostsSelectedTotal = 'Selected / Total : %d / %d';

  rsConfirmCaption = 'Confirm';

  rsConfirmHostForgetsPackages = 'Are you sure you want to forget %s packages from host %s ?';
  rsForgetPackageError = 'Error while forgetting package %s: %s';
  rsConfirmPackageEdit = 'Do you want to download and edit the package %s ?';

  rsPrivateKeyDoesntExist = 'Private key doesn''t exist : %s';

  rsConfirmImportCaption = 'Confirm import';
  rsConfirmImport = 'Are you sure you want to import'#13#10'%s'#13#10' to your repository ?';
  rsImportingFile = 'Importing %s';
  rsUploadingPackagesToWaptSrv = 'Uploading %s packages to WAPT server...';
  rsSuccessfullyImported = '%s successfully imported.';
  rsFailedImport = 'Error during import.';
  rsFailedExternalRepoUpdate = 'Unable to get Packages index from %';

  rsWaptPackagePrefixMissing = 'You must first define the Package prefix in preferences';

  rsPackageSourcesAvailable = 'The package sources are available in %s';
  rsPackageBuiltSourcesAvailable = 'The package is built and uploaded and sources are available in %s';
  rsInstallerFileNotFound =  'The installer filename %s does not exists !';

  rsConfirmRmPackagesFromHost = 'Are you sure you want to remove %s package(s) from the selected host(s) %s ?';
  rsPackageRemoveError = 'Error while removing package %s: %s';

  rsConfirmPackageInstall = 'Are you sure you want to install/upgrade %s package(s) for the selected host(s) %s ?';
  rsPackageInstallError = 'Error while triggering package install/upgrade %s: %s';



  rsReallowPackagesOnHost = 'Selection of package(s) to remove from conflict list';
  rsRmBundleFromHosts = 'Selection of package bundles for removing from the selected hosts';
  rsNoBundle = 'There is no package bundle.'; // 'Il n''y a aucun groupe.'; TODO : pas assez explicite ?

  rsWaptClientUpdateOnHosts = 'Updating WAPT client on the hosts';

  rsTriggerHostsUpdate = 'Trigger packages list update on the hosts';
  rsTriggerHostsUpgrade = 'Trigger installed packages upgrade on the hosts';

  rsTriggerWAPTWUA_Scan = 'Trigger the scan of missing Windows Updates';
  rsTriggerWAPTWUA_Download = 'Trigger the download of missing Windows Updates';
  rsTriggerWAPTWUA_Install = 'Trigger the installation of missing Windows Updates';

  rsTriggerWakeonlan = 'Send a WakeOnlan packet to hosts';

  rsConfirmRmHostsFromList = 'Are you sure you want to remove %s hosts from the list ?';
  rsConfirmRmHostsPackagesFromList = 'Are you sure you want to remove %s hosts and matching configuration packages from the server ?';

  rsUninstallingPackage = 'Uninstalling %s...';

  rsCanceledByUser = 'Task %s has been canceled by the user';

  rsFilterAll = '(All)';

  rsAddADSGroups = 'This will get the Active Directory groups of each selected host and '+LineEnding+
        'add the matching Wapt packages to dependencies of the host'+LineEnding+
        'if the package exists.'+LineEnding+''+LineEnding+
        'Are you sure to continue ?';

  { Messages dans wapt-get/waptcommon.pas }
  rsInnoSetupUnavailable = 'Innosetup is unavailable (path : %s), please install it first.';
  rsUndefWaptSrvInIni = 'wapt_server is not defined in your %s ini file';
  rsDlStoppedByUser = 'Download stopped by the user';
  rsCertificateCopyFailure = 'Couldn''t copy certificate %s to %s.';

  { Messages dans uVisCreateKey }
  rsInputKeyName = 'Please input a key name.';
  rsInputCommonName = 'Please input a Common Name to identify signer';
  rsKeyAlreadyExists = 'Key %s already exists, please pick another name.';

  rsReloadWaptconsoleConfig = 'Reloading WaptConsole configuration';
  rsReloadWaptserviceConfig = 'Reloading WaptService configuration';

  { Messages dans uVisEditPackage.pas }
  rsEditBundle = 'Edit package bundle.';
  rsEdPackage = 'Package bundle';
  rsPackagesNeededCaption = 'Packages needed in package bundle';

  rsEditHostCaption = 'Edit host';
  rsUpgradingHost = 'Upgrade triggered on the remote host.';
  rsUpgradeHostError = 'Failed to trigger upgrade : %s';
  rsEditHostError =  'Unable to edit the host package %s.'#13#10'If package is signed with a foreign key, you may want to delete host package first to workaround the issue...';

  rsSaveMods = 'Save changes ?';
  rsUploading = 'Uploading';
  rsPackageCreationError = 'Error while building package : %s';
  rsHostConfigEditCaption = 'Edit host configuration';
  rsPackagesNeededOnHostCaption = 'Packages needed on host';

  rsDownloading = 'Downloading';
  rsBundleConfigEditCaption = 'Edit package bundle configuration';
  rsDlCanceled = 'Download canceled.';
  rsIgnoredPackages = 'Warning : couldn''t find package(s) %s ; ignoring them.';
  rsIgnoredConfictingPackages = 'Warning : couldn''t find package(s) %s ; conflicting package(s) have been ignored.';
  rsDownloadCurrupted = 'Downloaded file %s is corrupted. MD5 mismatch.';

  { Messages dans uVisEditPackage.pas }
  rsInputPubKeyPath = 'Please input path to public key';
  rsInvalidWaptSetupDir = 'WAPTsetup directory is not valid : %s';

  { Messages dans uVisChangePassword.pas }
  rsDiffPwError = 'Passwords do not match.';
  rsEmptyNewPwError = 'New password must not be empty.';
  rsEmptyOldPwError = 'Old password must not be empty.';
  rsIncorrectOldPwError = 'Old password is incorrect.';

  { Messages dans uVisApropos }
  rsVersion = 'Waptconsole version : %s'#13#10'Wapt-get version: %s';

  { Messages dans uVisApropos }
  rsUrl = 'Url : %s';
  rsPackageDuplicateConfirmCaption = 'Confirm duplication of package';
  rsPackageDuplicateConfirm = 'Are you sure you want to duplicate the package(s)'#13#10'%s'#13#10' into your repository ?';
  rsDownloadingPackage = 'Package(s) %s is being downloaded.';
  rsDuplicating = 'Package(s) %s is being duplicated.';
  rsDuplicateSuccess = 'Package(s) %s successfully duplicated.';
  rsDuplicateFailure = 'Error while duplicating the package(s).';
  rsNoPackage = 'No package found. Check authorized certificates';



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


  rsDefaultUsageStatsURL = 'http://wapt.tranquil.it/usage_stats';

implementation

end.


