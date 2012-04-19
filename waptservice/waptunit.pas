unit WaptUnit; 

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, IdHTTPServer, DaemonApp, IdCustomHTTPServer, IdContext;

type

  { TWaptDaemon }

  TWaptDaemon = class(TDaemon)
    IdHTTPServer1: TIdHTTPServer;
    procedure DataModuleCreate(Sender: TObject);
    procedure IdHTTPServer1CommandGet(AContext: TIdContext;
      ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
  private
    { private declarations }
  public
    { public declarations }
  end; 

var
  WaptDaemon: TWaptDaemon;

implementation

procedure RegisterDaemon; 
begin
  RegisterDaemonClass(TWaptDaemon)
end;

{ TWaptDaemon }

procedure TWaptDaemon.DataModuleCreate(Sender: TObject);
begin

end;

procedure TWaptDaemon.IdHTTPServer1CommandGet(AContext: TIdContext;
  ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
begin
  AResponseInfo.ContentText:='Un texte de reponse';
  AResponseInfo.ResponseNo:=200;
end;


{$R *.lfm}


initialization
  RegisterDaemon; 
end.

