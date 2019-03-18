unit uWaptTrayRes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, DefaultTranslator;

resourcestring

  { --- MESSAGES DANS LE TRAY WAPT --- }
  rsUpdatesAvailableFor = 'Available updates for :'#13#10'-%s';
  rsErrorFor = 'Error for %s';
  rsError = 'Error';
  rsTaskStarted = '%s started';
  rsTaskInProgress = '%s in progress';
  rsTaskDone = '%s done'#13#10'%s';
  rsCanceling = 'Canceling %s';
  rsNoTaskCanceled = 'No task canceled';
  rsPackageConfigDone = 'Done configuring packages for the current user session';
  rsPackageConfigError = 'Error while configuring packages for the current user session';
  rsWaptServiceTerminated = 'WAPTService terminated';
  rsChecking = 'Checking...';
  rsErrorWhileChecking = 'Error while checking...';
  rsInstalling = 'Install in progess';
  rsPendingInstalls = 'Pending packages installs: %s';
  rsPendingRemoves = 'Pending packages removes: %s';
  rsPendingWUAUpdates = 'Pending WUA updates: %s';
  rsStartingWaptService = 'Starting WAPTService';
  rsStoppingWaptService = 'Stopping WAPTService';
  rsWaptServiceStarted = 'WAPTService started';
  rsWaptServiceStopped = 'WAPTService stopped';

implementation

end.


