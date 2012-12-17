unit WaptMapper; 

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, DaemonApp; 

type

  { TDaemonMapper1 }

  TDaemonMapper1 = class(TDaemonMapper)
    procedure DaemonMapper1Create(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end; 

var
  DaemonMapper1: TDaemonMapper1; 

implementation

procedure RegisterMapper; 
begin
  RegisterDaemonMapper(TDaemonMapper1)
end;

{ TDaemonMapper1 }

procedure TDaemonMapper1.DaemonMapper1Create(Sender: TObject);
begin

end;

{$R *.lfm}


initialization
  RegisterMapper; 
end.

