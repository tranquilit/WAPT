unit uWaptRes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, DefaultTranslator;

resourcestring

  { Messages dans uwaptconsole.pas }
  rsFatalError = 'Failed to recover action.'; // '... Impossible de récupérer l''action.';
  rsInstalling = 'Installing %s...';
  rsDefineWaptdevPath = 'Please choose a development directory to edit group package.'; //'Veuillez définir un répertoire de développement pour pouvoir éditer un paquet groupe.'

  rsPublicKeyGenSuccess = 'Key %s successfully created.';
  rsPublicKeyGenFailure = 'Failed to generate public key.';
  rsPublicKeyGenError = 'Error during key generation : %s';

  rsCreationInProgress = 'Creating...'; //'Création en cours'
  rsProgressTitle = 'Uploading to WAPT server...';
  rsWaptSetupUploadSuccess = 'WAPT agent successfully created and uploaded.'; // 'Agent WAPT créé et déposé avec succès : %s';
  rsWaptUploadError = 'Error while uploading agent'; // 'Erreur lors du dépôt de l''agent WAPT : %s';
  rsWaptSetupError = 'Error while creating agent'; // 'Erreur à la création de l''agent WAPT : %s';

  rsForcedUninstallPackages = 'Mark packages for forced uninstall'; // 'Choix des paquets à forcer à désintaller sur les postes sélectionnés'; TODO
  rsDependencies = 'Mark packages for adding as dependencies for selected hosts'; // 'Choix des paquets à ajouter en dépendance aux postes sélectionnés';
  rsNbModifiedHosts = '%s hosts affected.';
  rsTaskCancelled = 'Task canceled.';
  rsFailedToCancel = 'Could not cancel : %s.';

  rsIncorrectPassword = 'Password incorrect.';
  rsPasswordChangeSuccess = 'Password successfully updated !';
  rsPasswordChangeError = 'Error : %s';

  rsWaptAgentUploadSuccess = 'Successfully uploaded WAPT agent !';
  rsWaptAgentUploadError = 'Error while uploading WAPT agent : %s';
  rsWaptAgentSetupSuccess = 'waptagent.exe successfully created : %s';
  rsWaptAgentSetupError = 'Error while creating waptagent.exe: %s';

  rsConfirmRmOnePackage = 'Are you sure you want to remove this package from server ?';
  rsConfirmRmMultiplePackages = 'Are you sure you want to remove these packages from server ?'; // Maybe consider merging the last two into a single formatted str.
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

  rsConfirmRmPackagesFromHost = 'Are you sure you want to remove %s packages from host %s ?';
  rsPackageRemoveError = 'Error while removing package %s: %s';

  rsReallowPackagesOnHost = 'Mark packages for reallowing on selected hosts'; // 'Choix des paquets à réautoriser sur les postes sélectionnés';
  rsRmGroupFromHosts = 'Mark groups for removing from selected hosts'; // 'Choix des groupes à enlever des postes sélectionnés';
  rsNoGroup = 'There is no group.'; // 'Il n''y a aucun groupe.'; TODO : pas assez explicite ?

  rsWaptClientUpdateOnHosts = 'Updating WAPT client on hosts'; //'Mise à jour du client WAPT sur les postes';

  rsConfirmRmHostsFromList = 'Are you sure you want to remove %s hsots from the list ?';

  rsUninstallingPackage = 'Uninstalling %s...';

  rsCanceledByUser = 'Task %s has been canceled by user';

  { Messages dans wapt-get/waptcommon.pas }
  rsInnoSetupUnavailable = 'Innosetup is unavailable (path : %s), please install it.';
  rsUndefWaptSrvInIni = 'wapt_server is not defined in your %s ini file';
  rsDlStoppedByUser = 'Download stopped by user';
  rsCertificateCopyFailure = 'Copie du certificat de %s vers %s impossible';

  { Messages dans uVisCreateKey }
  rsInputKeyName = 'Please input a key name'; // 'Veuillez rentrer un nom de clé'; // TODO
  rsKeyAlreadyExists = 'Key %s already exists, please pick another name.';

  { Messages dans uVisEditPackage.pas }
  rsEditGroup = 'Edit group';
  rsEdPackage = 'Group';
  rsPackagesNeededCaption = 'Packages needed in group';

  rsEditHostCaption = 'Edit host';
  rsUpgradingHost = 'Upgrading';
  rsUpgradeHostError = 'Failed to upgrade host : ';

  rsSaveMods = 'Save changes ?';
  rsUploading = 'Uploading';
  rsPackageCreationError = 'Error while creating package : %s';
  rsHostConfigEditCaption = 'Edit host configuration';
  rsPackagesNeededOnHostCaption = 'Packages needed on host';

  rsDownloading = 'Downloading';
  rsGroupConfigEditCaption = 'Edit group configuration';
  rsDlCanceled = 'Download canceled.';
  rsIgnoredPackages = 'Warning : couldn''t find packages %s ; ignoring them.';
  rsIgnoredConfictingPackages = 'Warning : couldn''t find packages %s ; ignored from conflicting packages.'; // TODO

  { Messages dans uVisEditPackage.pas }
  rsInputPubKeyPath = 'Please input path to public key';
  rsInvalidWaptSetupDir = 'WAPTsetup directory is not valid : %s'; // 'Le répertoire pour sauvegarder waptsetup n''est pas valide: %s';

  { Messages dans uVisChangePassword.pas }
  rsDiffPwError = 'Passwords do not match.';
  rsEmptyNewPwError = 'New password may not be empty.';
  rsEmptyOldPwError = 'Old password may not be empty.';
  rsIncorrectOldPwError = 'Old password is incorrect.';

  { Messages dans uVisApropos }
  rsVersion = 'Version Waptconsole: %s'#13#10'Version Wapt-get: %s';

  { Messages dans uVisApropos }
  rsUrl = 'Url : %s';
  rsPackageDuplicateConfirmCaption = 'Confirm duplication';
  rsPackageDuplicateConfirm = 'Are you sure you want to duplicate'#13#10'%s'#13#10' into your repository ?'; // TODO : 'in' vs 'into' ?
  rsDownloadingPackage = 'Downloading %s';
  rsDuplicating = 'Duplicating %s';
  rsDuplicateSuccess = '%s successfully duplicated.';
  rsDuplicateFailure = 'Error while duplicating.';



implementation

end.

