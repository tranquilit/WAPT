unit constants;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

const

  LANGUAGE_EN               : integer = 1;
  LANGUAGE_FR               : integer = 2;
  LANGUAGE_DE               : integer = 3;

  DIALOG_TITLE          : String = 'Validation';
  PROTOCOLS             : array[0..1] of String = ( 'http', 'https' );
  MIME_APPLICATION_JSON : String = 'application/json';
  HTTP_TIMEOUT          : integer = 1 * 500;
  HTTP_RESPONSE_CODE_OK : integer = 200;
  HTML_NO_DOC           : String = '<HTML><HEAD><HEAD><BODY><BODY></HTML>';

var
  LANGUAGE_ID : integer = 0;


resourcestring
    rs_port_is_used  =   'There already is a Web server listening on  '+ #13#10#13#10 + '%s:%d' + #13#10#13#10 +
                            'You have several choices: abort the installation, ignore this warning (NOT RECOMMENDED), ' +
                            'deactivate the conflicting service and replace it with our bundled Nginx server, or choose ' +
                            'not to install Nginx.  In the latter case it is advised to set up your Web server as a reverse ' +
                            'proxy to ' + #13#10#13#10 + 'http://localhost:8080/';
    rs_error_list_iface =  'A problem has occured while getting list of network interfaces';
    rs_error_not_a_valid_port = '%d is not a valid port number' + #13#10 + 'Please select a port number between 1-65535';

    rs_welcome = 'Welcome';



function TranslateConsts( k : AnsiString; v: AnsiString; hash: Longint; data: Pointer): AnsiString;


implementation

uses Dialogs;


function TranslateConsts( k : AnsiString; v: AnsiString; hash: Longint; data: Pointer): AnsiString;
begin
  case LANGUAGE_ID of

  // FR
  2:
    begin
      if      'constants.rs_welcome' = k then
        result := 'Bienvenue'
      else if 'constants.rs_port_is_used' = k then
        result := 'Il y a déjà un serveur en écoute sur' + #13#10#13#10 + '%s:%d' + #13#10#13#10 +
                  'Vous avez plusieurs choix : abandonner l''installation, ignorer cet avertissement(Non recommandé), ' +
                  'désactiver le service conflictuel et le remplacer avec notre serveur Nginx embarqué, ou ' +
                  'ne pas installer Nginx. Dans ce dernier cas il vous faudra vous assuer de configuer vôtre ' +
                  'serveur web comme un proxy vers' + #13#10#13#10 +
                  'http://localhost:8080'

      else if 'constants.rs_error_list_iface' = k then
        result := 'Un problème est servenu lors de la récupération de la liste de interfaces réseaux'

      else if 'constants.rs_error_not_a_valid_port' = k then
        result := '%d n''est pas un port valide.' +#13#10 + 'Veuillez sélectionner un numéro de port en 1 et 65535';
    end;
  else
    result := v;
  end;


end;




end.

