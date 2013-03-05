unit waptwmi;
{ -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.

#    from http://theroadtodelphi.wordpress.com/wmi-delphi-code-creator/
#    Author Rodrigo Ruz rodrigo.ruz.v@gmail.com


#    WAPT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WAPT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WAPT.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------
}

{$mode objfpc}{$H+}

// from http://theroadtodelphi.wordpress.com/wmi-delphi-code-creator/
// Author Rodrigo Ruz rodrigo.ruz.v@gmail.com


interface

uses
  SysUtils,
  ActiveX,
  ComObj,
  Variants,windows,
  superobject;



function VarArrayToStr(const vArray: variant): string;
function GetWMIObject(const objectName: AnsiString): IDispatch; //create the Wmi instance
function VarStrNull(const V:OleVariant):string; //avoid problems with null strings

Function WMIBaseBoardInfo:ISUperObject;


implementation


function VarArrayToStr(const vArray: variant): string;

    function _VarToStr(const V: variant): string;
    var
    Vt: integer;
    begin
    Vt := VarType(V);
        case Vt of
          varSmallint,
          varInteger  : Result := IntToStr(integer(V));
          varSingle,
          varDouble,
          varCurrency : Result := FloatToStr(Double(V));
          varDate     : Result := VarToStr(V);
          varOleStr   : Result := WideString(V);
          varBoolean  : Result := VarToStr(V);
          varVariant  : Result := VarToStr(Variant(V));
          varByte     : Result := char(byte(V));
          varString   : Result := String(V);
          varArray    : Result := VarArrayToStr(Variant(V));
        end;
    end;

var
i : integer;
begin
    Result := '[';
     if (VarType(vArray) and VarArray)=0 then
       Result := _VarToStr(vArray)
    else
    for i := VarArrayLowBound(vArray, 1) to VarArrayHighBound(vArray, 1) do
     if i=VarArrayLowBound(vArray, 1)  then
      Result := Result+_VarToStr(vArray[i])
     else
      Result := Result+'|'+_VarToStr(vArray[i]);

    Result:=Result+']';
end;

function VarStrNull(const V:OleVariant):string; //avoid problems with null strings
begin
  Result:='';
  if not VarIsNull(V) then
  begin
    if VarIsArray(V) then
       Result:=VarArrayToStr(V)
    else
    Result:=VarToStr(V);
  end;
end;

function GetWMIObject(const objectName: AnsiString): IDispatch; //create the Wmi instance
var
  chEaten: PULong;
  BindCtx: IBindCtx;
  Moniker: IMoniker;
begin
  OleCheck(CreateBindCtx(0, bindCtx));
  OleCheck(MkParseDisplayName(BindCtx, StringToOleStr(objectName), chEaten, Moniker));
  OleCheck(Moniker.BindToObject(BindCtx, nil, IDispatch, Result));
end;

Function WMIBaseBoardInfo:ISUperObject;
var
  objWMIService : OLEVariant;
  colItems      : OLEVariant;
  colItem       : Variant;
  oEnum         : IEnumvariant;
  iValue        : PULong;
begin;
  result := TSuperObject.Create;
  objWMIService := GetWMIObject('winmgmts:\\localhost\root\CIMV2');
  colItems      := objWMIService.ExecQuery('SELECT * FROM Win32_BaseBoard','WQL',0);
  oEnum         := IUnknown(colItems._NewEnum) as IEnumVariant;
  while oEnum.Next(1, colItem, iValue) = 0 do
  begin
    result.S['Caption'] := VarStrNull(colItem.Caption);// String
    result.S['ConfigOptions'] :=  VarStrNull(colItem.ConfigOptions);// String
    result.S['CreationClassName'] :=  VarStrNull(colItem.CreationClassName);// String
    result.S['Depth'] :=  VarStrNull(colItem.Depth);// Real32
    result.S['Description'] :=  VarStrNull(colItem.Description);// String
    result.S['Height'] :=  VarStrNull(colItem.Height);// Real32
    result.S['HostingBoard'] :=  VarStrNull(colItem.HostingBoard);// Boolean
    result.S['HotSwappable'] :=  VarStrNull(colItem.HotSwappable);// Boolean
    result.S['InstallDate'] :=  VarStrNull(colItem.InstallDate);// Datetime
    result.S['Manufacturer'] :=  VarStrNull(colItem.Manufacturer);// String
    result.S['Model'] :=  VarStrNull(colItem.Model);// String
    result.S['Name'] :=  VarStrNull(colItem.Name);// String
    result.S['OtherIdentifyingInfo'] :=  VarStrNull(colItem.OtherIdentifyingInfo);// String
    result.S['PartNumber'] :=  VarStrNull(colItem.PartNumber);// String
    result.S['PoweredOn'] :=  VarStrNull(colItem.PoweredOn);// Boolean
    result.S['Product'] :=  VarStrNull(colItem.Product);// String
    result.S['Removable'] :=  VarStrNull(colItem.Removable);// Boolean
    result.S['SerialNumber'] :=  VarStrNull(colItem.SerialNumber);// String
    result.S['SKU'] :=  VarStrNull(colItem.SKU);// String
    result.S['Status'] :=  VarStrNull(colItem.Status);// String
    result.S['Tag'] :=  VarStrNull(colItem.Tag);// String
    result.S['Version'] := VarStrNull(colItem.Version);// String
  end;
end;

initialization
  CoInitialize(nil);

finalization;
  CoUninitialize;
end.

