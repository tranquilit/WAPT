{ This file was automatically created by Lazarus. Do not edit!
  This source is only used to compile and install the package.
 }

unit pltis_wapt;

{$warn 5023 off : no warning about unused units}
interface

uses
  waptwinutils, NetworkAdapterInfo, uWaptRes, waptcommon, waptdb, uwaptcrypto, 
  uWaptPythonUtils, uWAPTPollThreads, LazarusPackageIntf;

implementation

procedure Register;
begin
end;

initialization
  RegisterPackage('pltis_wapt', @Register);
end.
