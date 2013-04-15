unit soutils;
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

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils,SuperObject,DB;

function StringList2SuperObject(St:TStringList):ISuperObject;
function SplitLines(St:String):ISuperObject;
//function Split(St:String;Sep:String):ISuperObject;

function Dataset2SO(DS:TDataset;AllRecords:Boolean=True):ISuperObject;
procedure SO2Dataset(SO:ISuperObject;DS:TDataset;ExcludedFields:Array of String);

implementation
uses StrUtils,tisStrings;


function StringList2SuperObject(St: TStringList): ISuperObject;
var
  i:integer;
begin
  Result := TSuperObject.Create(stArray);
  for i:=0 to st.Count-1 do
    Result.AsArray.Add(st[i]);
end;

function SplitLines(St: String): ISuperObject;
var
  tok : String;
begin
  Result := TSuperObject.Create(stArray);
  St := StrUtils.StringsReplace(St,[#13#10,#13,#10],[#13,#13,#13],[rfReplaceAll]);
  repeat
    tok := StrToken(St,#13);
    Result.AsArray.Add(tok);
  until St='';
end;

function Split(St: String; Sep: Char): ISuperObject;
var
  tok : String;
begin
  Result := TSuperObject.Create(stArray);
  repeat
    tok := StrToken(St,Sep);
    Result.AsArray.Add(tok);
  until St='';
end;

type
  StrArray = Array of String;

function Split(St: String; Sep: Char): StrArray;
var
  tok : String;
  len : integer;
begin
  len := 0;
  repeat
    SetLength(Result,0);
    inc(len);
    tok := StrToken(St,Sep);
    Result[len] := tok;
  until St='';
end;

function Dataset2SO(DS: TDataset;AllRecords:Boolean=True): ISuperObject;
var
  rec: ISuperObject;

  procedure Fillrec(rec:ISuperObject);
  var
    i:integer;
  begin
    for i:=0 to DS.Fields.Count-1 do
    begin
      if DS.Fields[i].IsNull then
        rec.N[DS.Fields[i].fieldname] := Nil
      else
      case DS.Fields[i].DataType of
        ftString : rec.S[DS.Fields[i].fieldname] := UTF8Decode(DS.Fields[i].AsString);
        ftInteger : rec.I[DS.Fields[i].fieldname] := DS.Fields[i].AsInteger;
        ftFloat : rec.D[DS.Fields[i].fieldname] := DS.Fields[i].AsFloat;
        ftBoolean : rec.B[DS.Fields[i].fieldname] := DS.Fields[i].AsBoolean;
        ftDateTime : rec.S[DS.Fields[i].fieldname] :=  DelphiDateTimeToISO8601Date(DS.Fields[i].AsDateTime);
      else
        rec.S[DS.Fields[i].fieldname] := UTF8Decode(DS.Fields[i].AsString);
      end;
    end;
  end;

begin
  if AllRecords then
  begin
    DS.First;
    Result := TSuperObject.Create(stArray);
    While not DS.EOF do
    begin
      rec := TSuperObject.Create(stObject);
      Result.AsArray.Add(rec);
      Fillrec(Rec);
      DS.Next;
    end;
  end
  else
  begin
    Result := TSuperObject.Create;
    Fillrec(Result);
  end;
end;

procedure SO2Dataset(SO: ISuperObject; DS: TDataset;ExcludedFields:Array of String);
var
  arec : ISuperObject;
  procedure Fillrec(rec:ISuperObject);
  var
    i:integer;
    dt : TDateTime;
  begin
    for i:=0 to DS.Fields.Count-1 do
    begin
      if StrIsOneOf(DS.Fields[i].fieldname,ExcludedFields) then
        Continue;
      if rec.AsObject.Exists(DS.Fields[i].fieldname) then
      begin
        if ObjectIsNull(rec.N[DS.Fields[i].fieldname]) then
          DS.Fields[i].Clear
        else
        case DS.Fields[i].DataType of
          ftString : DS.Fields[i].AsString := UTF8Encode(rec.S[DS.Fields[i].fieldname]);
          ftInteger : DS.Fields[i].AsInteger := rec.I[DS.Fields[i].fieldname];
          ftFloat : DS.Fields[i].AsFloat := rec.D[DS.Fields[i].fieldname];
          ftBoolean : DS.Fields[i].AsBoolean := rec.B[DS.Fields[i].fieldname];

          ftDateTime : if ISO8601DateToDelphiDateTime(rec.S[DS.Fields[i].fieldname],dt) then
            DS.Fields[i].AsDateTime := dt;
        else
          DS.Fields[i].AsString := UTF8Encode(rec.S[DS.Fields[i].fieldname]);
        end
      end
    end;
  end;

begin
  // If SO is an array, we fill the dataset with all records
  if SO.DataType = stArray then
  begin
    for arec in SO do
    begin
      DS.Append;
      Fillrec(ARec);
      DS.Post;
    end;
  end
  else
  begin
    // If SO is a single object, we fill the dataset with one record
    if not (DS.State in dsEditModes) then
      DS.Append;
    Fillrec(SO);
    DS.Post;
  end;
end;



end.

