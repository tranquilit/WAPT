program WmiDelphiWin32_LateBinding;
{ -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
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

{$APPTYPE CONSOLE}

uses
  SysUtils,
  ActiveX,
  ComObj,
  Variants,windows,
  waptwmi, superobject
  ;//introduced in delphi 6, if you use a older version of delphi you just remove this

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

function GetWMIObject(const objectName: String): IDispatch; //create the Wmi instance
var
  chEaten: PULong;
  BindCtx: IBindCtx;
  Moniker: IMoniker;
begin
  OleCheck(CreateBindCtx(0, bindCtx));
  OleCheck(MkParseDisplayName(BindCtx, StringToOleStr(objectName), chEaten, Moniker));
  OleCheck(Moniker.BindToObject(BindCtx, nil, IDispatch, Result));
end;

//The Win32_BaseBoard class represents a base board (also known as a motherboard
//or system board).

procedure  GetWin32_BaseBoardInfo;
var
  objWMIService : OLEVariant;
  colItems      : OLEVariant;
  colItem       : Variant;
  oEnum         : IEnumvariant;
  iValue        : PULong;
begin;
  objWMIService := GetWMIObject('winmgmts:\\localhost\root\CIMV2');
  colItems      := objWMIService.ExecQuery('SELECT * FROM Win32_BaseBoard','WQL',0);
  oEnum         := IUnknown(colItems._NewEnum) as IEnumVariant;
  while oEnum.Next(1, colItem, iValue) = 0 do
  begin
    Writeln(Format('Caption                  %s',[VarStrNull(colItem.Caption)]));// String
    Writeln(Format('ConfigOptions            %s',[VarStrNull(colItem.ConfigOptions)]));// String
    Writeln(Format('CreationClassName        %s',[VarStrNull(colItem.CreationClassName)]));// String
    Writeln(Format('Depth                    %s',[VarStrNull(colItem.Depth)]));// Real32
    Writeln(Format('Description              %s',[VarStrNull(colItem.Description)]));// String
    Writeln(Format('Height                   %s',[VarStrNull(colItem.Height)]));// Real32
    Writeln(Format('HostingBoard             %s',[VarStrNull(colItem.HostingBoard)]));// Boolean
    Writeln(Format('HotSwappable             %s',[VarStrNull(colItem.HotSwappable)]));// Boolean
    Writeln(Format('InstallDate              %s',[VarStrNull(colItem.InstallDate)]));// Datetime
    Writeln(Format('Manufacturer             %s',[VarStrNull(colItem.Manufacturer)]));// String
    Writeln(Format('Model                    %s',[VarStrNull(colItem.Model)]));// String
    Writeln(Format('Name                     %s',[VarStrNull(colItem.Name)]));// String
    Writeln(Format('OtherIdentifyingInfo     %s',[VarStrNull(colItem.OtherIdentifyingInfo)]));// String
    Writeln(Format('PartNumber               %s',[VarStrNull(colItem.PartNumber)]));// String
    Writeln(Format('PoweredOn                %s',[VarStrNull(colItem.PoweredOn)]));// Boolean
    Writeln(Format('Product                  %s',[VarStrNull(colItem.Product)]));// String
    Writeln(Format('Removable                %s',[VarStrNull(colItem.Removable)]));// Boolean
    Writeln(Format('Replaceable              %s',[VarStrNull(colItem.Replaceable)]));// Boolean
    Writeln(Format('RequirementsDescription  %s',[VarStrNull(colItem.RequirementsDescription)]));// String
    Writeln(Format('RequiresDaughterBoard    %s',[VarStrNull(colItem.RequiresDaughterBoard)]));// Boolean
    Writeln(Format('SerialNumber             %s',[VarStrNull(colItem.SerialNumber)]));// String
    Writeln(Format('SKU                      %s',[VarStrNull(colItem.SKU)]));// String
    Writeln(Format('SlotLayout               %s',[VarStrNull(colItem.SlotLayout)]));// String
    Writeln(Format('SpecialRequirements      %s',[VarStrNull(colItem.SpecialRequirements)]));// Boolean
    Writeln(Format('Status                   %s',[VarStrNull(colItem.Status)]));// String
    Writeln(Format('Tag                      %s',[VarStrNull(colItem.Tag)]));// String
    Writeln(Format('Version                  %s',[VarStrNull(colItem.Version)]));// String
    Writeln(Format('Weight                   %s',[VarStrNull(colItem.Weight)]));// Real32
    Writeln(Format('Width                    %s',[VarStrNull(colItem.Width)]));// Real32
    Writeln('');
    colItem:=Unassigned;
  end;
end;

procedure  GetWin32_RoutingTable;
var
  objWMIService : OLEVariant;
  colItems      : OLEVariant;
  colItem       : Variant;
  oEnum         : IEnumvariant;
  iValue        : PULong;
begin;
  objWMIService := GetWMIObject('winmgmts:\\localhost\root\CIMV2');
  colItems      := objWMIService.ExecQuery('Select * from Win32_IP4RouteTable','WQL',0);
  oEnum         := IUnknown(colItems._NewEnum) as IEnumVariant;
  while oEnum.Next(1, colItem, iValue) = 0 do
  begin
      Writeln(Format('Age: %s',[VarStrNull(colItem.Age)]));
      Writeln(Format('Description: %s',[VarStrNull(colItem.Description)]));
      Writeln(Format('Destination: %s',[VarStrNull(colItem.Destination)]));
      Writeln(Format('Information: %s',[VarStrNull(colItem.Information)]));
      Writeln(Format('InterfaceIndex: %s',[VarStrNull(colItem.InterfaceIndex)]));
      Writeln(Format('Mask: %s',[VarStrNull(colItem.Mask)]));

      Writeln(Format('Name: %s',[VarStrNull(colItem.Name)]));
      Writeln(Format('Next Hop: %s',[VarStrNull(colItem.NextHop)]));
      Writeln(Format('Protocol: %s',[VarStrNull(colItem.Protocol)]));
      //Writeln(Format('Type: %s',[VarStrNull(colItem.Type)]));

    Writeln('');
    colItem:=Unassigned;
  end;
end;


begin
 writeln(WMIBaseBoardInfo.AsJSon(True));
 try
    CoInitialize(nil);
    try
      //GetWin32_BaseBoardInfo;
      Readln;
    finally
    CoUninitialize;
    end;
 except
    on E:Exception do
    begin
        Writeln(E.Classname, ':', E.Message);
        Readln;
    end;
  end;
end.
