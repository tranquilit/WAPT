unit uWaptExitRes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, DefaultTranslator;

resourcestring

  { --- MESSAGES DANS WAPTEXIT --- }
  rsCheckingUpgrades = 'Checking if WAPT Packages installs or updates are pending.';
  rsWaptServiceNotRunning = 'WAPTService is not running';
  rsWaptUpgradespending = 'Some upgrades are pending, launch upgrades after timeout expired or manual action';
  rsUpdatingSoftware = 'Updating software';
  rsInterruptUpdate = 'Interrupt software update';
  rsClosing = 'Closing...';
  rsSoftwareUpdateIn = 'Updating software in %s sec...';
  rsLaunchSoftwareUpdate = 'Launch software update';
  rsErrorWininetFlags = 'Internal error in SetToIgnoreCerticateErrors when trying to get wininet flags. %s';
  rsUpdatesAvailable = '%d WAPT installs or updates pending';
  rsPendingRemoves = '%d packages to uninstall';
  rsWUAUpdatesAvailable = '%d Windows Updates pending';
  rsUpgradeRunning = 'Upgrade running...';
  rsErrorTriggeringTask = 'Error triggering action: %s';

implementation

end.

