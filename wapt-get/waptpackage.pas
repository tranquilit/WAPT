unit waptpackage;

{$mode objfpc}{$H+}

interface
uses
  Classes, SysUtils;



Type
  { TWaptPackage }
  TWaptPackage = class(TObject)
  private
    Fcontrol: String;
    Fdescription: String;
    Fpackage: String;
    FPackageFilename: String;
    FUnpackedPath: String;
    Fversion: String;
    procedure Setcontrol(AValue: String);
    procedure Setdescription(AValue: String);
    procedure Setpackage(AValue: String);
    procedure SetPackageFilename(AValue: String);
    procedure SetUnpackedPath(AValue: String);
    procedure Setversion(AValue: String);
  public
    property PackageFilename:String read FPackageFilename write SetPackageFilename;
    property UnpackedPath:String read FUnpackedPath write SetUnpackedPath;

    property package: String read Fpackage write Setpackage;
    property version: String read Fversion write Setversion;
    property description: String read Fdescription write Setdescription;


    property control: String read Fcontrol write Setcontrol;

    constructor create(AFilename:String);
    destructor Destroy; override;

    function Unpack(target:String = ''):String;
    procedure Build;
    procedure Sign(PrivateKeyPath:String);
    function Check(sslCertsPath:String):String;

  end;


implementation

{ TWaptPackage }

procedure TWaptPackage.Setcontrol(AValue: String);
begin
  if Fcontrol=AValue then Exit;
  Fcontrol:=AValue;
end;

procedure TWaptPackage.Setdescription(AValue: String);
begin
  if Fdescription=AValue then Exit;
  Fdescription:=AValue;
end;

procedure TWaptPackage.Setpackage(AValue: String);
begin
  if Fpackage=AValue then Exit;
  Fpackage:=AValue;
end;

procedure TWaptPackage.SetPackageFilename(AValue: String);
begin
  if FPackageFilename=AValue then Exit;
  FPackageFilename:=AValue;
end;

procedure TWaptPackage.SetUnpackedPath(AValue: String);
begin
  if FUnpackedPath=AValue then Exit;
  FUnpackedPath:=AValue;
end;

procedure TWaptPackage.Setversion(AValue: String);
begin
  if Fversion=AValue then Exit;
  Fversion:=AValue;
end;

constructor TWaptPackage.create(AFilename: String);
begin

end;

destructor TWaptPackage.Destroy;
begin
  inherited Destroy;
end;

function TWaptPackage.Unpack(target: String): String;
begin

end;

procedure TWaptPackage.Build;
begin

end;

procedure TWaptPackage.Sign(PrivateKeyPath: String);
begin

end;

function TWaptPackage.Check(sslCertsPath: String): String;
begin

end;


end.

