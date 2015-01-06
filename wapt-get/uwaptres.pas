unit uWaptRes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

resourcestring
  // Messages dans uwaptconsole.pas
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
  rsFailedToCancel = 'Impossible d''annuler: %s.';
  rsIncorrectPassword = 'Mauvais mot de passe';
  rsPasswordChangeSuccess = 'Le mot de passe a été changé avec succès !';
  rsPasswordChangeError = 'Erreur : %s';
  rsWaptAgentUploadSuccess = 'Waptagent déposé avec succès';
  rsWaptAgentUploadError = 'Erreur lors du dépôt de waptagent: %s';
  rsWaptAgentSetupSuccess = 'waptagent.exe créé avec succès: ';
  rsWaptAgentSetupError = 'Erreur à la création du waptagent.exe: %s';


  rsCanceledByUser = 'Task %s has been canceled by user';

implementation

end.

