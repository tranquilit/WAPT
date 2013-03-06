unit waptcommon;
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
     interfaces,Classes, SysUtils,
     DB,sqldb,sqlite3conn,SuperObject;

  const
    waptservice_port:integer = 8088;

  Function  FindWaptRepo:String;
  Function  GetWaptServerURL:String;

  function WaptgetPath: Utf8String;
  function WaptDBPath: Utf8String;

  //function http_post(url: string;Params:String): String;

  function LocalSysinfo: ISuperObject;

type

  { TWAPTDB }
  TWAPTDB = class(TObject)
  private
    fsqltrans : TSQLTransaction;
    fdb : TSQLite3Connection;
    procedure CreateTables;
  public
    constructor create(dbpath:String);
    destructor Destroy; override;

    // initializes DB and create missing tables
    procedure OpenDB;

    // execute SQL query and returns a JSON structure with records (stArray)
    function Select(SQL:String):ISuperObject;
    function QueryCreate(SQL:String):TSQLQuery;

    // backup existing data as JSON structure, renames old DB and recreates one, restores data
    procedure upgradedb;

    function dumpdb:ISuperObject;

    property db:TSQLite3Connection read FDB;
    property sqltrans:TSQLTransaction read fsqltrans;
  end;



implementation

uses FileUtil,soutils,tiscommon,JCLSysInfo,  Windows, ActiveX, ComObj, Variants;

function FindWaptRepo: String;
begin
  if Wget_try('http://wapt/wapt') then
    Result := 'http://wapt/wapt'
  else
    result := 'http://wapt.tranquil.it/wapt';
end;

function GetWaptServerURL: String;
begin
  result := 'http://wapt/waptserver';
end;


function WaptgetPath: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0))+'\wapt-get.exe'
end;

function WaptDBPath: Utf8String;
begin
  result := ExtractFilePath(ParamStr(0))+'\db\waptdb.sqlite'
end;

{
idHttp,
function http_post(url: string;Params:String): String;
var
  St:TMemoryStream;
  http:TIdHTTP;
  paramsStream:TStringStream;
begin
  try
    http := Nil;
    paramsStream := Nil;
    http:=TIdHTTP.Create(Nil);
    paramsStream := TStringStream.Create(Params);
    HTTP.Request.ContentType := 'application/x-www-form-urlencoded';

    //http.AllowCookies := True;
    //http.CookieManager := session_cookies;

    result := http.Post(url,paramsStream);
  finally
    if paramsStream<>Nil then
      paramsStream.Free;
    http.DisconnectNotifyPeer;
    if http<>Nil then
      http.Free;
  end;
end;
}


{ waptdb }

constructor Twaptdb.create(dbpath:String);
begin
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
  OpenDB;
end;

procedure TWAPTDB.OpenDB;
begin
  db.KeepConnection := False;
  db.Transaction := SQLTrans;
  sqltrans.DataBase := db;
  db.Open;
  CreateTables;
end;

destructor Twaptdb.Destroy;
begin
  db.Close;
  if Assigned(db) then
    db.free;
  if Assigned(sqltrans) then
    sqltrans.free;

  inherited Destroy;
end;

procedure TWAPTDB.CreateTables;
var
  lst : TStringList;
begin
  lst := TStringList.create;
  try
    db.GetTableNames(lst,False);
    if lst.IndexOf('wapt_repo')<0 then
    begin
      db.ExecuteDirect('CREATE TABLE wapt_repo ('+
        'id INTEGER PRIMARY KEY AUTOINCREMENT,'+
        'Package VARCHAR(255),'+
        'Version VARCHAR(255),'+
        'Section VARCHAR(255),'+
        'Priority VARCHAR(255),'+
        'Architecture VARCHAR(255),'+
        'Maintainer VARCHAR(255),'+
        'Description VARCHAR(255),'+
        'Filename VARCHAR(255),'+
        'Size INTEGER,'+
        'MD5sum VARCHAR(255),'+
        'Depends VARCHAR(800),'+
        'Sources VARCHAR(255),'+
        'repo_url VARCHAR(255)'+
        ')'
        );
      db.ExecuteDirect('create index idx_repo_package on wapt_repo(Package,Version)');
    end;

    if lst.IndexOf('wapt_localstatus')<0 then
    begin
      db.ExecuteDirect('CREATE TABLE wapt_localstatus ('+
        'id INTEGER PRIMARY KEY AUTOINCREMENT,'+
        'Package VARCHAR(255),'+
        'Version VARCHAR(255),'+
        'InstallDate VARCHAR(255),'+
        'InstallStatus VARCHAR(255),'+
        'InstallOutput TEXT,'+
        'InstallParams VARCHAR(800),'+
        'UninstallString varchar(255),'+
        'UninstallKey varchar(255)'+
        ')');
        db.ExecuteDirect('create index idx_localstatus_package on wapt_localstatus(Package,Version)');
    end;
  finally
    if sqltrans.Active then
      sqltrans.Commit;

    lst.Free;
  end;
end;

function TWAPTDB.Select(SQL: String): ISuperObject;
var
  query : TSQLQuery;
begin
  Query := TSQLQuery.Create(Nil);
  try
    Query.DataBase := db;
    Query.Transaction := sqltrans;

    Query.SQL.Text:=SQL;
    Query.Open;
    Result := Dataset2SO(Query);

  finally
    Query.Free;
  end;
end;

function TWAPTDB.QueryCreate(SQL: String): TSQLQuery;
begin
  Result := TSQLQuery.Create(Nil);
  Result.DataBase := db;
  Result.Transaction := sqltrans;
  Result.SQL.Text:=SQL;
  if (SQL<>'') and (pos('select',lowercase(SQL))=1) then
    Result.Open;
end;

procedure TWAPTDB.upgradedb;
var
  databackup : ISuperObject;
  tablename:ISuperObject;
  query : TSQLQuery;
  oldfn : String;

begin
  DataBackup := dumpdb;
  try
    writeln(databackup.AsJSon(True));
    db.Close;
    oldfn := ChangeFileExt(db.DatabaseName,'')+'-'+FormatDateTime('yyyymmdd-hhnnss',Now)+'.sqlite';
    if RenameFileUTF8(db.DatabaseName,oldfn) then
    try
      OpenDB;
      try
        //temporary bufds to insert records
        Query := TSQLQuery.Create(Nil);
        Query.DataBase := db;
        Query.Transaction := sqltrans;

        // recreates data from JSON backup using TBufDataset
        for tablename in databackup.AsObject.GetNames do
        begin
          Query.Close;
          Query.SQL.Text:= 'select * from '+tablename.AsString;
          Query.Open;
          SO2Dataset(databackup[tablename.AsString],Query,['id']);
          Query.ApplyUpdates;
          if query.ChangeCount>0 then
            Raise Exception.Create('Erreur enregistrement pour '+tablename.AsString);
        end;
      finally
        Query.Free;
      end;
    except
      // if error, roolback to old db file
      if FileExists(db.DatabaseName) then
        DeleteFileUTF8(db.DatabaseName);
      RenameFileUTF8(oldfn,db.DatabaseName);
      raise;
    end
    else
      Raise Exception.Create('Base '+db.DatabaseName+' verrouillée');
  finally
    if sqltrans.Active then
      sqltrans.commit;
  end;

end;

function TWAPTDB.dumpdb: ISuperObject;
var
  tables:TStringList;
  i:integer;
begin
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
end;

//////

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
  chEaten: PULONG;
  BindCtx: IBindCtx;
  Moniker: IMoniker;
begin
  OleCheck(CreateBindCtx(0, bindCtx));
  OleCheck(MkParseDisplayName(BindCtx, StringToOleStr(objectName), chEaten, Moniker));
  OleCheck(Moniker.BindToObject(BindCtx, nil, IDispatch, Result));
end;

function GetWin32_BIOSInfo:ISuperObject;
var
  objWMIService : OleVariant;
  colItems      : OleVariant;
  colItem       : Variant;
  oEnum,pEnum   : IEnumvariant;
  sValue        : string;
  p             : Variant;
  i:integer;
begin;
  Result := TSuperObject.Create;
  objWMIService := GetWMIObject('winmgmts:\\localhost\root\CIMV2');
  colItems      := objWMIService.ExecQuery('SELECT * FROM Win32_BIOS','WQL',0);
  oEnum         := IUnknown(colItems._NewEnum) as IEnumVariant;

  while oEnum.Next(1, colItem, nil) = 0 do
  begin
    Result.S['Manufacturer'] := VarStrNull(colItem.Properties_.Item('Manufacturer').Value);
    //Result.S['Manufacturer'] := VarStrNull(colItem.Properties_.Item('Manufacturer').Value);
    Result.S['SerialNumber'] := VarStrNull(colItem.Properties_.Item('SerialNumber').Value);
    colItem:=Unassigned;
  end;
end;



function LocalSysinfo: ISUperObject;
var
      so:ISuperObject;
      CPUInfo:TCpuInfo;
      Cmd,IPS:String;
      st : TStringList;
begin
  so := TSuperObject.Create;
  so.S['workgroupname'] := GetWorkGroupName;
  so.S['localusername'] := TISGetUserName;
  so.S['computername'] :=  TISGetComputerName;
  so.S['systemmanufacturer'] := GetSystemManufacturer;
  so.S['systemproductname'] := GetSystemProductName;
  so.S['biosversion'] := GetBIOSVersion;
  so.S['biosdate'] := DelphiDateTimeToISO8601Date(GetBIOSDate);
  // redirect to a dummy file just to avoid a console creation... bug of route ?
  //so['routingtable'] := SplitLines(RunTask('route print > dummy',ExitStatus));
  //so['ipconfig'] := SplitLines(RunTask('ipconfig /all > dummy',ExitStatus));
  ST := TStringList.Create;
  try
    GetIpAddresses(St);
    so['ipaddresses'] := StringList2SuperObject(St);
  finally
    St.free;
  end;
  St := TStringList.Create;
  try
    GetMacAddresses('',St);
    so['macaddresses'] := StringList2SuperObject(St);
  finally
    St.free;
  end;

  so.I['processorcount'] := ProcessorCount;
  GetCpuInfo(CPUInfo);
  so.S['cpuname'] := Trim(CPUInfo.CpuName);
  so.I['physicalmemory'] := GetTotalPhysicalMemory;
  so.I['virtualmemory'] := GetTotalVirtualMemory;
  so.S['waptgetversion'] := ApplicationVersion(WaptgetPath);
  so.S['biosinfo'] := GetBIOSExtendedInfo;

  so['wmibiosinfo'] := GetWin32_BIOSInfo;

  // Pose probleme erreur OLE "syntaxe incorrecte"
  //so['wmi_baseboardinfo'] := WMIBaseBoardInfo;
  result := so;
end;

initialization
  if not Succeeded(CoInitializeEx(nil, COINIT_MULTITHREADED)) then;
    //Raise Exception.Create('Unable to initialize ActiveX layer');

finalization
  CoUninitialize();
end.

