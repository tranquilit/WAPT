unit uWaptRes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

resourcestring

  { Messages dans uwaptconsole.pas }
  rsFatalError = '... Impossible de récupérer l''action.';
  rsInstalling = 'Installing %s...';
  rsDefineWaptdevPath = 'Veuillez définir un répertoire de développement pour pouvoir éditer un paquet groupe.';

  rsPublicKeyGenSuccess = 'Key %s successfully created.';
  rsPublicKeyGenFailure = 'Failed to generate public key.';
  rsPublicKeyGenError = 'Erreur à la création de la clé : %s';

  rsCreationInProgress = 'Création en cours';
  rsProgressTitle = 'Dépôt sur le serveur WAPT en cours';
  rsWaptSetupUploadSuccess = 'Agent WAPT créé et déposé avec succès : %s';
  rsWaptUploadError = 'Erreur lors du dépôt de l''agent WAPT : %s';
  rsWaptSetupError = 'Erreur à la création de l''agent WAPT : %s';

  rsForcedUninstallPackages = 'Choix des paquets à forcer à désintaller sur les postes sélectionnés';
  rsDependencies = 'Choix des paquets à ajouter en dépendance aux postes sélectionnés';
  rsNbModifiedHosts = '%s postes modifiés.';
  rsTaskCancelled = 'Task canceled.';
  rsFailedToCancel = 'Impossible d''annuler : %s.';

  rsIncorrectPassword = 'Mauvais mot de passe';
  rsPasswordChangeSuccess = 'Le mot de passe a été changé avec succès !';
  rsPasswordChangeError = 'Erreur : %s';

  rsWaptAgentUploadSuccess = 'Waptagent déposé avec succès';
  rsWaptAgentUploadError = 'Erreur lors du dépôt de waptagent: %s';
  rsWaptAgentSetupSuccess = 'waptagent.exe créé avec succès: ';
  rsWaptAgentSetupError = 'Erreur à la création du waptagent.exe: %s';

  rsConfirmRmOnePackage = 'Etes-vous sûr de vouloir supprimer ce paquet du serveur ?';
  rsConfirmRmMultiplePackages = 'Etes-vous sûr de vouloir supprimer ces paquets du serveur ?'; // Maybe consider merging the last two into a single formatted str.
  rsConfirmRmPackageCaption = 'Confirmer la suppression';
  rsDeletionInProgress = 'Suppression des paquets...';
  rsDeletingElement = 'Suppression de %s';
  rsUpdatingPackageList = 'Mise à jour de la liste des paquets';
  rsDisplaying = 'Affichage';
  rsConfirmDeletion = 'Confirmer la suppression';

  rsConfirmCaption = 'Confirmer';

  rsConfirmHostForgetsPackages = 'Confirmez-vous l''oubli de %s packages du poste %s ?'; // Possible issue with multiple formatting parameters
  rsForgetPackageError = 'Erreur pour le package %s: %s';

  rsPrivateKeyDoesntExist = 'La clé privée n''existe pas : s';

  rsConfirmImportCaption = 'Confirmer l''import';
  rsConfirmImport = 'Etes vous sûr de vouloir importer'#13#10'%s'#13#10' dans votre dépôt ?';
  rsImportingFile = 'Importing %s';
  rsUploadingPackagesToWaptSrv = 'Dépôt sur le serveur WAPT en cours pour %s paquets...';
  rsSuccessfullyImported = '%s importé(s) avec succès.';
  rsFailedImport = 'Erreur lors de l''import.';

  rsConfirmRmPackagesFromHost = 'Confirmez-vous la désinstallation de %s packages du poste %s ?';
  rsPackageRemoveError = 'Erreur pour le package %s: %s';

  rsReallowPackagesOnHost = 'Choix des paquets à réautoriser sur les postes sélectionnés';
  rsRmGroupFromHosts = 'Choix des groupes à enlever des postes sélectionnés';
  rsNoGroup = 'Il n''y a aucun groupe.';

  rsWaptClientUpdateOnHosts = 'Mise à jour du client WAPT sur les postes';

  rsConfirmRmHostsFromList = 'Confirmez-vous la suppression de %s postes de la liste ?';

  rsUninstallingPackage = 'Désinstallation de %s en cours ...';

  rsCanceledByUser = 'Task %s has been canceled by user';

  { Messages dans wapt-get/waptcommon.pas }
  rsInnoSetupUnavailable = 'Innosetup n''est pas disponible (emplacement %s), veuillez l''installer';
  rsUndefWaptSrvInIni = 'wapt_server is not defined in your %s ini file';
  rsDlStoppedByUser = 'Download stopped by user';

  { Messages dans uVisCreateKey }
  rsInputKeyName = 'Veuillez rentrer un nom de clé';
  rsKeyAlreadyExists = 'La clé %s existe déjà, choisir un autre nom de clé';

  { Messages dans uVisEditPackage.pas }
  rsEditGroup = 'Editer le groupe';
  rsEdPackage = 'Groupe';
  rsPackagesNeededCaption = 'Paquets devant être présents dans le groupe';

  rsEditHostCaption = 'Editer la machine';
  rsUpgradingHost = 'Upgrade lancée';
  rsUpgradeHostError = 'Impossible de lancer l''upgrade sur la machine: ';

  rsSaveMods = 'Sauvegarder les modifications ?';
  rsUploading = 'Upload en cours';
  rsPackageCreationError = 'Problème lors de la création du paquet: %s';
  rsHostConfigEditCaption = 'Modifier la configuration de la machine';
  rsPackagesNeededOnHostCaption = 'Paquets devant être présents sur la machine';

  rsDownloading = 'Téléchargement en cours';
  rsGroupConfigEditCaption = 'Modifier la configuration du groupe';
  rsDlCanceled = 'Téléchargement annulé';
  rsIgnoredPackages = 'Attention, les paquets %s ont été ignorés car introuvables';
  rsIgnoredConfictingPackages = 'Attention, les paquets %s ont été ignorés des paquets interdits car introuvables';

  { Messages dans uVisEditPackage.pas }
  rsInputPubKeyPath = 'Veuillez rentrer le chemin vers la clé publique';
  rsInvalidWaptSetupDir = 'Le répertoire pour sauvegarder waptsetup n''est pas valide: ';

  { Messages dans uVisChangePassword.pas }
  rsDiffPwError = 'Les mots de passe sont différents';
  rsEmptyNewPwError = 'Le nouveau mot de passe ne doit pas être vide';
  rsEmptyOldPwError = 'L''ancien mot de passe ne doit pas être vide';
  rsIncorrectOldPwError = 'L''ancien mot de passe ne correspond pas';

implementation

end.

