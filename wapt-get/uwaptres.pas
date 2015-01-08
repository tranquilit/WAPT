unit uWaptRes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, DefaultTranslator;

resourcestring

  { Messages dans uwaptconsole.pas }
  rsFatalError = 'Failed to recover action.'; // '... Impossible de récupérer l''action.';
  rsInstalling = 'Installing %s...';
  rsDefineWaptdevPath = 'Please select a directory on your package development host before editing a package bundle.'; //'Veuillez définir un répertoire de développement pour pouvoir éditer un paquet groupe.'

  rsPublicKeyGenSuccess = 'Key %s has been successfully created.';
  rsPublicKeyGenFailure = 'The generation of the public key has failed.';
  rsPublicKeyGenError = 'Error during key generation : %s';

  rsCreationInProgress = 'Creating...'; //'Création en cours'
  rsProgressTitle = 'Uploading to WAPT server...';
  rsWaptSetupUploadSuccess = 'WAPT agent successfully created and uploaded to the repository : %s'; // 'Agent WAPT créé et déposé avec succès : %s';
  rsWaptUploadError = 'Error while uploading agent to the repository : %s'; // 'Erreur lors du dépôt de l''agent WAPT : %s';
  rsWaptSetupError = 'Error while creating agent : %s'; // 'Erreur à la création de l''agent WAPT : %s';

  rsForcedUninstallPackages = 'Select packages to force-remove from the hosts'; // 'Choix des paquets à forcer à désintaller sur les postes sélectionnés'; TODO
  rsDependencies = 'Select packages to add to the hosts as dependencies'; // 'Choix des paquets à ajouter en dépendance aux postes sélectionnés';
  rsNbModifiedHosts = '%s hosts affected.';
  rsTaskCancelled = 'Task canceled.';
  rsFailedToCancel = 'Could not cancel : %s.';

  rsIncorrectPassword = 'Incorrect password.';
  rsPasswordChangeSuccess = 'Password successfully updated !';
  rsPasswordChangeError = 'Error : %s';

  rsWaptAgentUploadSuccess = 'Successfully uploaded WAPT agent !';
  rsWaptAgentUploadError = 'Error while uploading WAPT agent : %s';
  rsWaptAgentSetupSuccess = 'waptagent.exe successfully created : %s';
  rsWaptAgentSetupError = 'Error while creating waptagent.exe: %s';

  rsConfirmRmOnePackage = 'Are you sure you want to remove this package from the server ?';
  rsConfirmRmMultiplePackages = 'Are you sure you want to remove the selected packages from the server ?'; // Maybe consider merging the last two into a single formatted str.
  rsConfirmRmPackageCaption = 'Confirm removal';
  rsDeletionInProgress = 'Removing packages...';
  rsDeletingElement = 'Removing %s';
  rsUpdatingPackageList = 'Updating package list';
  rsDisplaying = 'Displaying';
  rsConfirmDeletion = 'Confirm removal';  // Duplicate of rsConfirmRmPackageCaption

  rsConfirmCaption = 'Confirm';

  rsConfirmHostForgetsPackages = 'Are you sure you want to forget %s packages from host %s ?'; // Possible issue with multiple formatting parameters
  rsForgetPackageError = 'Error while forgetting package %s: %s';

  rsPrivateKeyDoesntExist = 'Private key doesn''t exist : %s';

  rsConfirmImportCaption = 'Confirm import';
  rsConfirmImport = 'Are you sure you want to import'#13#10'%s'#13#10' to your repository ?';
  rsImportingFile = 'Importing %s';
  rsUploadingPackagesToWaptSrv = 'Uploading %s packages to WAPT server...';
  rsSuccessfullyImported = '%s successfully imported.';
  rsFailedImport = 'Error during import.';

  rsConfirmRmPackagesFromHost = 'Are you sure you want to remove %s package(s) from the selected host(s) %s ?';
  rsPackageRemoveError = 'Error while removing package %s: %s';

  rsReallowPackagesOnHost = 'Select package(s) to remove from conflict list'; // 'Choix des paquets à réautoriser sur les postes sélectionnés';
  rsRmGroupFromHosts = 'Select groups for removing from selected hosts'; // 'Choix des groupes à enlever des postes sélectionnés';
  rsNoGroup = 'There is no group.'; // 'Il n''y a aucun groupe.'; TODO : pas assez explicite ?

  rsWaptClientUpdateOnHosts = 'Updating WAPT client on hosts'; //'Mise à jour du client WAPT sur les postes';

  rsConfirmRmHostsFromList = 'Are you sure you want to remove %s hosts from the list ?';

  rsUninstallingPackage = 'Uninstalling %s...';

  rsCanceledByUser = 'Task %s has been canceled by the user';

  { Messages dans wapt-get/waptcommon.pas }
  rsInnoSetupUnavailable = 'Innosetup is unavailable (path : %s), please install it first.';
  rsUndefWaptSrvInIni = 'wapt_server is not defined in your %s ini file';
  rsDlStoppedByUser = 'Download stopped by the user';
  rsCertificateCopyFailure = 'Couldn''t copy certificate %s to %s.';

  { Messages dans uVisCreateKey }
  rsInputKeyName = 'Please input a key name'; // 'Veuillez rentrer un nom de clé'; // TODO
  rsKeyAlreadyExists = 'Key %s already exists, please pick another name.';

  { Messages dans uVisEditPackage.pas }
  rsEditGroup = 'Edit group';
  rsEdPackage = 'Group';
  rsPackagesNeededCaption = 'Packages needed in package bundle'; // TODO refactoring

  rsEditHostCaption = 'Edit host';
  rsUpgradingHost = 'Upgrade triggered on the remote host.'; // Mise à jour lancée
  rsUpgradeHostError = 'Failed to trigger upgrade : %s';

  rsSaveMods = 'Save changes ?';
  rsUploading = 'Uploading';
  rsPackageCreationError = 'Error while creating package : %s';
  rsHostConfigEditCaption = 'Edit host configuration';
  rsPackagesNeededOnHostCaption = 'Packages needed on host';

  rsDownloading = 'Downloading';
  rsGroupConfigEditCaption = 'Edit package bundle configuration';
  rsDlCanceled = 'Download canceled.';
  rsIgnoredPackages = 'Warning : couldn''t find package(s) %s ; ignoring them.';
  rsIgnoredConfictingPackages = 'Warning : couldn''t find package(s) %s ; conflicting package(s) have been ignored.'; // TODO

  { Messages dans uVisEditPackage.pas }
  rsInputPubKeyPath = 'Please input path to public key';
  rsInvalidWaptSetupDir = 'WAPTsetup directory is not valid : %s'; // 'Le répertoire pour sauvegarder waptsetup n''est pas valide: %s';

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
  rsPackageDuplicateConfirm = 'Are you sure you want to duplicate the package(s)'#13#10'%s'#13#10' into your repository ?'; // TODO : 'in' vs 'into' ?
  rsDownloadingPackage = 'Package(s) %s is being downloaded.';
  rsDuplicating = 'Package(s) %s is being duplicated.';
  rsDuplicateSuccess = 'Package(s) %s successfully duplicated.';
  rsDuplicateFailure = 'Error while duplicating the package(s).';



implementation

end.

