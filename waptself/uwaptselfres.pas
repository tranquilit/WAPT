unit uWaptSelfRes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

resourcestring
 rsLogin = 'Login';
 rsPassword = 'Password';
 rsForce = 'An operation has failed do you want to force the installation/removal?'+chr(13)+'Operation : %s';
 rsSortByDateAsc = 'Sort by date : asc';
 rsSortByDateDesc = 'Sort by date : desc';
 rsTaskBar = 'Task bar';
 rsStatusInstalled = 'Installed';
 rsActionUpgrade = 'Upgrade';
 rsActionRemove = 'Remove';
 rsActionInstall = 'Install';
 rsImpacted_processes = 'Some processes (see list below) may be closed during installation/removal.'+Chr(13)+'Do you want to continue ?'+Chr(13)+'Impacted processes : %s';
 rsErrorTriggeringTask = 'Error triggering action: %s';
 rsWaitingInstall = 'Waiting for install...';
 rsWaitingRemove = 'Waiting for uninstall...';
 rsWarningNoLoginOrPassword = 'Please enter a login/password';
 rsAllCategories = 'All';
 rsWarningPasswordLoginBlank = 'Your password or login is empty';
 rsServiceNotRun = 'The service is probably not started, try again?';
 rsNO_RULES = 'There is no rules for self-service';
 rsWRONG_PASSWORD_USERNAME = 'Wrong username or password';

implementation

end.

