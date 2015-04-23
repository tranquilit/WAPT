unit waptdb;
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
     Classes, SysUtils, Windows,
     DB,sqldb,sqlite3conn,SuperObject,syncobjs,IdComponent,tiscommon,tisstrings, DefaultTranslator;

type
  TFormatHook = Function(Dataset:TDataset;Data,FN:Utf8String):UTF8String of object;

  { TWAPTDB }
  TWAPTDB = class(TObject)
  private
    fsqltrans : TSQLTransaction;
    fdb : TSQLite3Connection;
    dbinuse : TCriticalSection;
    function QueryCreate(SQL: String): TSqlQuery;
    property db:TSQLite3Connection read fDB;
    property sqltrans:TSQLTransaction read fsqltrans;
  public
    constructor create(dbpath:String);
    destructor Destroy; override;

    // execute SQL query and returns a JSON structure with records (stArray)
    function Select(SQL:String):ISuperObject;
    function dumpdb:ISuperObject;

    procedure SetParam(name,value:String);
    function GetParam(name:String):String;

    function QueryToHTMLtable(SQL: String; FormatHook: TFormatHook=nil): String;
  end;


implementation

uses FileUtil, soutils, Variants, ShellApi, JwaIpHlpApi,
  JwaIpTypes, NetworkAdapterInfo, registry, JwaWinDNS, JwaWinsock2,
  IdHttp,IdSSLOpenSSL,IdMultipartFormData,IdExceptionCore,IdException,Dialogs,UnitRedirect, IdURI,
  uwaptres,gettext,IdStack,waptwinutils,tisinifiles;

constructor TWAPTDB.create(dbpath:String);
begin
  dbinuse := syncobjs.TCriticalSection.Create;

  // The sqlite dll is either in the same dir as application, or in the DLLs directory, or relative to dbpath (in case of initial install)
  if FileExists(AppendPathDelim(ExtractFilePath(ParamStr(0)))+'sqlite3.dll') then
    SQLiteLibraryName:=AppendPathDelim(ExtractFilePath(ParamStr(0)))+'sqlite3.dll'
  else if FileExists(AppendPathDelim(ExtractFilePath(ParamStr(0)))+'DLLs\sqlite3.dll') then
    SQLiteLibraryName:=AppendPathDelim(ExtractFilePath(ParamStr(0)))+'DLLs\sqlite3.dll'
  else if FileExists(AppendPathDelim(ExtractFilePath(dbpath))+'..\DLLs\sqlite3.dll') then
    SQLiteLibraryName:=AppendPathDelim(ExtractFilePath(dbpath))+'..\DLLs\sqlite3.dll';

  fsqltrans := TSQLTransaction.Create(Nil);
  fdb := TSQLite3Connection.Create(Nil);
  db.LoginPrompt := False;
  if not DirectoryExists(ExtractFileDir(dbpath)) then
    mkdir(ExtractFileDir(dbpath));
  db.DatabaseName := dbpath;
  db.KeepConnection := False;
  db.Transaction := SQLTrans;
  sqltrans.DataBase := db;

end;

destructor TWAPTDB.Destroy;
begin
  try
    db.Close;
  finally
    dbinuse.Free;
    if Assigned(db) then
      db.free;
    if Assigned(sqltrans) then
      sqltrans.free;
  end;

  inherited Destroy;
end;

function TWAPTDB.Select(SQL: String): ISuperObject;
var
  query : TSQLQuery;
begin
  dbinuse.Acquire;
  try
    //db.Open;
    Query := TSQLQuery.Create(Nil);
    try
      Query.DataBase := db;
      Query.Transaction := sqltrans;

      Query.SQL.Text:=SQL;
      Query.Open;
      Result := Dataset2SO(Query);

    finally
      Query.Free;
      db.Close;
    end;
  finally
    dbinuse.Leave;
  end;
end;


function TWAPTDB.dumpdb: ISuperObject;
var
  tables:TStringList;
  i:integer;
begin
  dbinuse.Acquire;
  try
    Result := TSuperObject.Create;
    try
      tables := TStringList.Create;
      db.GetTableNames(tables);
      for i:=0 to tables.Count-1 do
        if tables[i] <> 'sqlite_sequence' then
          Result[tables[i]] := Select('select * from '+tables[i]);
    finally
      tables.Free;
    end;

  finally
    dbinuse.Release;
  end;
end;

procedure TWAPTDB.SetParam(name, value: String);
var
  q:TSQLQuery;
begin
  try
    dbinuse.Acquire;
    q := QueryCreate('insert or replace into wapt_params(name,value,create_date) values (:name,:value,:date)');
    try
      try
        q.ParamByName('name').AsString:=name;
        q.ParamByName('value').AsString:=value;
        q.ParamByName('date').AsString:=FormatDateTime('YYYYMMDD-hhnnss',Now);
        q.ExecSQL;
        sqltrans.Commit;
      except
        sqltrans.Rollback;
      end;
    finally
      q.Free;
    end;
  finally
    db.Close;
    dbinuse.Release;
  end;
end;

function TWAPTDB.GetParam(name: String): String;
var
  q:TSQLQuery;
begin
  try
    dbinuse.Acquire;
    result := '';
    q := QueryCreate('select value from wapt_params where name=:name');
    try
      try
        q.ParamByName('name').AsString:=name;
        q.open;
        Result := q.Fields[0].AsString;
        sqltrans.Commit;
      except
        sqltrans.Rollback;
      end;
    finally
      q.Free;
    end;

  finally
    db.Close;
    dbinuse.Release;
  end;
end;

function TWAPTDB.QueryCreate(SQL: String):TSQLQuery;
var
    ds:TSQLQuery;
begin
  ds := TSQLQuery.Create(Nil);
  ds.DataBase := db;
  ds.Transaction := sqltrans;
  ds.SQL.Text:=SQL;
  ds.ParseSQL:=True;
  ds.Open;
  result := ds;
end;

function TWAPTDB.QueryToHTMLtable(SQL: String;FormatHook: TFormatHook=Nil):String;
var
    ds:TSQLQuery;
    i:integer;
begin
  dbinuse.Acquire;
  try
    ds := TSQLQuery.Create(Nil);
    ds.DataBase := db;
    ds.Transaction := sqltrans;
    ds.SQL.Text:=SQL;
    ds.ParseSQL:=True;
    ds.Open;

    result := '<table><tr>';
    For i:=0 to ds.FieldCount-1 do
      if ds.Fields[i].Visible then
        Result := Result + '<th>'+ds.Fields[i].DisplayLabel+'</th>';
    result := Result+'</tr>';
    ds.First;
    while not ds.EOF do
    begin
      result := Result + '<tr>';
      For i:=0 to ds.FieldCount-1 do
        if ds.Fields[i].Visible then
        begin
          if Assigned(FormatHook) then
            Result := Result + '<td>'+FormatHook(ds,ds.Fields[i].AsString,ds.Fields[i].FieldName)+'</td>'
          else
            Result := Result + '<td>'+ds.Fields[i].AsString+'</td>';
        end;
      result := Result+'</tr>';
      ds.Next;
    end;
    result:=result+'</table>';
  finally
    db.Close;
    dbinuse.Release;
  end;
end;



initialization

finalization

end.

