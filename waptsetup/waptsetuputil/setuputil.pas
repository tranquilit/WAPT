unit setuputil;

{$mode objfpc}{$H+}

interface

uses
  IdHTTP,
  Classes,
  SysUtils;



function list_interfaces( sl: TStringList ): integer;
function http_create( https : boolean ) : TIdHTTP;
procedure http_free( var http  : TIdHTTP );
function wapt_ping( var success : boolean; url : String ): integer;

implementation



uses
  Dialogs,
  superobject,
  constants,
  IdSSLOpenSSL,
  Sockets,
  win32proc,
  JwaWindows;



function http_create( https : boolean ) : TIdHTTP;
var
  http : TIdHTTP;
  ssl  : TIdSSLIOHandlerSocketOpenSSL;
begin
  ssl := nil;

  http := TIdHTTP.Create;
  http.HandleRedirects  := True;
  http.ConnectTimeout   := HTTP_TIMEOUT;
  http.ReadTimeout      := HTTP_TIMEOUT;
  http.IOHandler        := nil;

  if https then
  begin
    ssl := TIdSSLIOHandlerSocketOpenSSL.Create;
    ssl.SSLOptions.Method := sslvSSLv23;
    http.IOHandler := ssl;
  end;


  result := http;
end;

procedure http_free( var http  : TIdHTTP );
begin
  if nil <> http.IOHandler then
  begin
    http.IOHandler.Free;
    http.IOHandler := nil;
  end;
  http.Free;
  http := nil;
end;


function wapt_ping( var success : boolean; url : String ): integer;
label
  LBL_ERROR,
  LBL_FAILED;
var
  bIsHTTP  : boolean;
  bIsHTTPS : boolean;
  http     : TIdHTTP;
  so       : ISuperObject;
  s        : String;
  r        : integer;
begin
  http := nil;

  url := Trim(url);
  if 0 = Length(url) then
    goto LBL_ERROR;

  bIsHTTP  := Pos( 'http://' , url ) = 1;
  bIsHTTPS := Pos( 'https://', url ) = 1;

  if not (bIsHTTP or bIsHTTPS) then
    goto LBL_ERROR;

  http := http_create( bIsHTTPS );
  try
    s := http.Get( url );
    r := 0;
  except
    r := -1;
  end;

  if 0 <> r then
    goto LBL_ERROR;

  if 0 = Length(s) then
    goto LBL_FAILED;

  if not (HTTP_RESPONSE_CODE_OK = http.ResponseCode) then
    goto LBL_FAILED;

  http_free( http );

  so := TSuperObject.ParseString( @WideString(s)[1], False );
  if not Assigned(so) then
    goto LBL_FAILED;

  so := so.O['result'];
  if not Assigned(so) then
    goto LBL_FAILED;

  so := so.O['version'];
  if not Assigned(so) then
    goto LBL_FAILED;

//  ShowMessage( 'Success ' + url );
  success := true;
  exit( 0 );

LBL_FAILED:
//  ShowMessage( 'LBL_FAILED ' + url );
  if Assigned(http) then
    http_free( http );
  success := false;
  exit( 0 );

LBL_ERROR:
//  ShowMessage( 'LBL_ERROR ' + url );
  if Assigned(http) then
    http_free( http );
  success := false;
  exit( -1 );
end;

function list_interfaces( sl: TStringList ): integer;
Var
    aSocket             : TSocket;
    aWSADataRecord      : WSAData;
    NoOfInterfaces      : Integer;
    NoOfBytesReturned   : DWORD;
    Buffer              : Array [0..30] of Interface_Info;
    i                   : Integer;
    ip                  : INT32;
    s                   : String;
Begin
  FillChar( aWSADataRecord, sizeof(WSAData), 0 );

  WSAStartup(MAKEWORD(2, 0), aWSADataRecord);

  aSocket := Socket (AF_INET, SOCK_STREAM, 0);

  If (aSocket = INVALID_SOCKET) then
    exit(-1);


  Try
    If WSAIoctl (aSocket, SIO_GET_INTERFACE_LIST, NIL, 0, @Buffer, 1024, NoOfBytesReturned, NIL, NIL) = SOCKET_ERROR then
    begin
      CloseSocket (aSocket);
      WSACleanUp;
      exit(-1);
    end;

    NoOfInterfaces := NoOfBytesReturned  Div SizeOf (INTERFACE_INFO);

    For i := 0 to NoOfInterfaces - 1 do
    Begin
      if IFF_UP <> ( IFF_UP and Buffer[i].iiFlags ) then
        continue;

      ip := INT32(  buffer[i].iiAddress.AddressIn.sin_addr );
      s := inet_ntoa( in_addr(ip)  );
      sl.Add( s  );
    end;
    result := 0;

  Except
    result := -1;
  end;

  CloseSocket (aSocket);
  WSACleanUp;
end;


end.

