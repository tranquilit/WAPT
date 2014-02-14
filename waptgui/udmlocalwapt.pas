unit uDMLocalWapt;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, sogrid,idhttp, IdAuthentication;

type

  { TDMLocalWapt }

  TDMLocalWapt = class(TDataModule)
    LocalWapt: TSOConnection;
    SODataSource1: TSODataSource;
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  DMLocalWapt: TDMLocalWapt;

implementation

{$R *.lfm}

end.

