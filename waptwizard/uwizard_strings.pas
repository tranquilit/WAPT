unit uwizard_strings;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

const

MSG_VALIDATE_PORT_IS_CLOSED_ON_ALL_INTERFACES : String = 'Validating that port %d is closed on all interfaces';
MSG_VALIDATE_PORT_IS_CLOSED_ON_INTERFACE      : String = 'Validating that port %d is closed on interface %s';
MSG_FAILED_TO_OBTAIN_NETWORK_INTERFACES_LIST  : String = 'Failed to obtain network interfaces list';
MSG_VALIDATE_PORT_IS_CLOSED                   : String = 'Validating that port %d is closed';
MSG_SOCKET_ERROR                              : String = 'Error %d - %s';
MSG_PORT_IS_NOT_CLOSED                        : String = 'Port %d on host %s is not closed, Select another port or check your configuration';
MSG_STARTING_SERVICE                          : String = 'Starting service %s';
MSG_STOPPING_SERVICE                          : String = 'Stopping service %s';
MSG_ERROR_WHILE_STARTING_SERVICE              : String = 'An error has occured while starting service %s';
MSG_ERROR_WHILE_STOPPING_SERVICE              : String = 'An error has occured while stapping service %s';
MSG_VALIDATING_PASSWORD                       : String = 'Validating password';
MSG_PASSWORD_MUST_BE_AT_LEAST_6_CHARS         : String = 'Password lentgh must be at least 6 characters';
MSG_UNEXPECTED_ERROR                          : String = 'An unexpected error has occurred %s';
MSG_WRITE_SERVER_CONFIGURATION                : String = 'Writing configuration file';

implementation

end.

