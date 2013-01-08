unit waptcommon;

{$mode objfpc}{$H+}
interface
  uses
     interfaces,Classes, SysUtils,
     DB,sqldb,sqlite3conn,SuperObject;

  const
    waptservice_port = 8088;

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

uses FileUtil,soutils,tiscommon,JCLSysInfo;

function FindWaptRepo: String;
begin
  if Wget_try('http://wapt/wapt') then
    Result := 'http://wapt/wapt'
  else
    result := 'http://srvinstallation.tranquil-it-systems.fr/wapt';
end;

function GetWaptServerURL: String;
begin
  result := 'http://wapt/waptserver';
end;


function WaptgetPath: Utf8String;
begin
  if FileExists(ExtractFilePath(ParamStr(0))+'\wapt-get.exe') then
    result := ExtractFilePath(ParamStr(0))+'\wapt-get.exe'
  else
    result := 'c:\wapt\wapt-get.exe';
end;

function WaptDBPath: Utf8String;
begin
  if FileExists(ExtractFilePath(ParamStr(0))+'\db\waptdb.sqlite') then
    result := ExtractFilePath(ParamStr(0))+'\db\waptdb.sqlite'
  else
    result := 'c:\wapt\db\waptdb.sqlite';

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

function LocalSysinfo: ISUperObject;
var
      so:ISuperObject;
      CPUInfo:TCpuInfo;
      Cmd,IPS:String;
      st : TStringList;
begin
  so := TSuperObject.Create;
  so.AsObject.S['workgroupname'] := GetWorkGroupName;
  so.AsObject.S['localusername'] := TISGetUserName;
  so.AsObject.S['computername'] :=  TISGetComputerName;
  so.AsObject.S['systemmanufacturer'] := GetSystemManufacturer;
  so.AsObject.S['systemproductname'] := GetSystemProductName;
  so.AsObject.S['biosversion'] := GetBIOSVersion;
  so.AsObject.S['biosdate'] := DelphiDateTimeToISO8601Date(GetBIOSDate);
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

  // Pose probleme erreur OLE "syntaxe incorrecte"
  //so['wmi_baseboardinfo'] := WMIBaseBoardInfo;
  result := so;
end;





end.

