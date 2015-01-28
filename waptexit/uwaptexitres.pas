unit uWaptExitRes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, DefaultTranslator;

resourcestring

  { --- MESSAGES DANS WAPTEXIT --- }
  rsUpdatingSoftware = 'Updating software';
  rsInterruptUpdate = 'Interrupt software update';
  rsSoftwareUpdateIn = 'Updating software in %s sec...';
  rsLaunchSoftwareUpdate = 'Launch software update';
  rsErrorWininetFlags = 'Internal error in SetToIgnoreCerticateErrors when trying to get wininet flags. %s';

implementation

end.

