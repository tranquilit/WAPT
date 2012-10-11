unit WaptUnit;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, ExtCtrls, IdHTTPServer, DaemonApp,
  IdCustomHTTPServer, IdContext, sqlite3conn, sqldb, db;

type

  { TWaptDaemon }

  TWaptDaemon = class(TDaemon)
    IdHTTPServer1: TIdHTTPServer;
    QLstLocalStatusid: TLongintField;
    QLstLocalStatusInstallDate: TStringField;
    QLstLocalStatusInstallStatus: TStringField;
    QLstLocalStatusPackage: TStringField;
    QLstLocalStatusRepoVersion: TStringField;
    QLstLocalStatusVersion: TStringField;
    QLstPackages: TSQLQuery;
    QLstLocalStatus: TSQLQuery;
    QLstPackagesArchitecture: TStringField;
    QLstPackagesDescription: TStringField;
    QLstPackagesFilename: TStringField;
    QLstPackagesid: TLongintField;
    QLstPackagesMaintainer: TStringField;
    QLstPackagesMD5sum: TStringField;
    QLstPackagesPackage: TStringField;
    QLstPackagesPriority: TStringField;
    QLstPackagesrepo_url: TStringField;
    QLstPackagesSection: TStringField;
    QLstPackagesSize: TLongintField;
    QLstPackagesVersion: TStringField;
    SQLTrans: TSQLTransaction;
    Timer1: TTimer;
    waptdb: TSQLite3Connection;
    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleStart(Sender: TCustomDaemon; var OK: Boolean);
    procedure IdHTTPServer1CommandGet(AContext: TIdContext;
      ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    procedure Timer1Timer(Sender: TObject);
  private
    { private declarations }
    inTimer:Boolean;
    function TableHook(Data, FN: Utf8String): Utf8String;
  public
    { public declarations }
  end; 

var
  WaptDaemon: TWaptDaemon;

implementation
uses Waptcommon, superobject,JclSysInfo,StrUtils,JCLRegistry,Windows,IdSocketHandle;

procedure RegisterDaemon;
begin
  RegisterDaemonClass(TWaptDaemon)
end;

Type TFormatHook = Function(Data,FN:Utf8String):UTF8String of object;



{ TWaptDaemon }
function DatasetToHTMLtable(ds:TDataset;FormatHook: TFormatHook=Nil):String;
var
    i:integer;
begin
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
          Result := Result + '<td>'+FormatHook(ds.Fields[i].AsString,ds.Fields[i].FieldName)+'</td>'
        else
          Result := Result + '<td>'+ds.Fields[i].AsString+'</td>';
      end;
    result := Result+'</tr>';
    ds.Next;
  end;
  result:=result+'</table>';
end;

procedure TWaptDaemon.DataModuleStart(Sender: TCustomDaemon; var OK: Boolean);
begin
//Application.Log(etInfo,'c:\wapt\wapt-get upgrade');
end;

procedure TWaptDaemon.DataModuleCreate(Sender: TObject);
var
    sh : TIdSocketHandle;
begin
  SQLiteLibraryName:=AppendPathDelim(ExtractFilePath(ParamStr(0)))+'DLLs\sqlite3.dll';
  IdHTTPServer1.DefaultPort:=waptservice_port;
  sh := IdHTTPServer1.Bindings.Add;
  sh.IP:='127.0.0.1';
  sh.Port:=waptservice_port;
  IdHTTPServer1.Active:=True;
end;

function GetSystemProductName: String;
const
  WinNT_REG_PATH = 'HARDWARE\DESCRIPTION\System\BIOS';
  WinNT_REG_KEY  = 'SystemProductName';
begin
  try
    Result := RegReadAnsiString(HKEY_LOCAL_MACHINE, WinNT_REG_PATH, WinNT_REG_KEY);
  except
    Result :='';
  end;
end;

function GetSystemManufacturer: String;
const
  WinNT_REG_PATH = 'HARDWARE\DESCRIPTION\System\BIOS';
  WinNT_REG_KEY  = 'SystemManufacturer';
begin
  try
    Result := RegReadAnsiString(HKEY_LOCAL_MACHINE, WinNT_REG_PATH, WinNT_REG_KEY);
  except
    Result :='';
  end;
end;

function GetBIOSVendor: String;
const
  WinNT_REG_PATH = 'HARDWARE\DESCRIPTION\System\BIOS';
  WinNT_REG_KEY  = 'BIOSVendor';
begin
  try
    Result := RegReadAnsiString(HKEY_LOCAL_MACHINE, WinNT_REG_PATH, WinNT_REG_KEY);
  except
    Result :='';
  end;
end;

function GetBIOSVersion: String;
const
  WinNT_REG_PATH = 'HARDWARE\DESCRIPTION\System\BIOS';
  WinNT_REG_PATH2 = 'HARDWARE\DESCRIPTION\System';
  WinNT_REG_KEY  = 'BIOSVersion';
  WinNT_REG_KEY2  = 'SystemBiosVersion';
begin
  try
    Result := RegReadAnsiString(HKEY_LOCAL_MACHINE, WinNT_REG_PATH, WinNT_REG_KEY);
  except
    try
      Result := RegReadAnsiMultiSz(HKEY_LOCAL_MACHINE, WinNT_REG_PATH2, WinNT_REG_KEY2);
    except
      Result :='';
    end;
  end;
end;

procedure TWaptDaemon.IdHTTPServer1CommandGet(AContext: TIdContext;
  ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
var
    ExitStatus:Integer;
    CPUInfo:TCpuInfo;
    St : TStringList;
    Cmd,IPS:String;
    i:integer;
    param,value,lst,UpgradeResult,SetupResult:String;
    so : ISuperObject;
begin
  //Default type
  AResponseInfo.ContentType:='text/html';
  if ARequestInfo.URI='/status' then
  try
    QLstLocalStatus.Close;
    QLstLocalStatus.Open;
    AResponseInfo.ContentText:=DatasetToHTMLtable(QLstLocalStatus,@TableHook);
  finally
    SQLTrans.Commit;
  end
  else
  if ARequestInfo.URI='/list' then
  try
    QLstPackages.Close;
    QLstPackages.Open;
    AResponseInfo.ContentText:=DatasetToHTMLtable(QLstPackages,@TableHook);
  finally
    SQLTrans.Commit;
  end
  else
  if ARequestInfo.URI='/upgrade' then
  begin
    UpgradeResult:=RunTask('c:\wapt\wapt-get --upgrade',ExitStatus);
    AResponseInfo.ContentType:='application/json';
    SO:=TSuperObject.Create;
    SO.S['operation'] := 'upgrade';
    SO['output'] := SplitLines(UpgradeResult);
    SO.I['exitstatus'] := ExitStatus;
    AResponseInfo.ContentText:=so.AsJSon(True);
  end
  else
  if ARequestInfo.URI='/waptupgrade' then
  begin
    AResponseInfo.ContentText:='Wapt Upgrade launched<br>'+
      RunTask('c:\wapt\wapt-get upgrade',ExitStatus);
  end
  else
  if ARequestInfo.URI='/waptupdate' then
  begin
    AResponseInfo.ContentText:='Wapt Update launched<br><pre>'+
      StringsReplace(RunTask('c:\wapt\wapt-get update',ExitStatus),[#13#10,#13,#10],['<br>','<br>','<br>'],[rfReplaceAll])+'</pre>';
  end
  else
  if ARequestInfo.URI='/sysinfo' then
  begin
    AResponseInfo.ContentType:='application/json';
    so := TSuperObject.Create;
    so.S['workgroupname'] := GetWorkGroupName;
    so.S['localusername'] := TISGetUserName;
    so.S['computername'] := TISGetComputerName;
    so.S['systemmanufacturer'] := GetSystemManufacturer;
    so.S['systemproductname'] := GetSystemProductName;
    so.S['biosversion'] := GetBIOSVersion;
    so.S['biosdate'] := DelphiDateTimeToISO8601Date(GetBIOSDate);
    // redirect to a dummy file just to avoid a console creation... bug of route ?
    so['routingtable'] := SplitLines(RunTask('route print > dummy',ExitStatus));
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
    AResponseInfo.ContentText:=so.AsJson(True);
  end
  else
  if ARequestInfo.URI='/install' then
  begin
    if not ARequestInfo.AuthExists or (ARequestInfo.AuthUsername <> 'admin') then
    begin
      AResponseInfo.ResponseNo := 401;
      AResponseInfo.ResponseText := 'Authorization required';
      AResponseInfo.ContentType := 'text/html';
      AResponseInfo.ContentText := '<html>Authentication required for Installation operations </html>';
      AResponseInfo.CustomHeaders.Values['WWW-Authenticate'] := 'Basic realm="WAPT-GET Authentication"';
      Exit;
    end;
    if ARequestInfo.Params.Count<=0 then
    begin
      AResponseInfo.ResponseNo := 404;
      AResponseInfo.ContentType := 'text/html';
      AResponseInfo.ContentText := '<html>Please provide a "package" parameter</html>';
      Exit;
    end;
    i:= ARequestInfo.Params.IndexOfName('package');
    cmd := 'c:\wapt\wapt-get install '+ARequestInfo.Params.ValueFromIndex[i];
    Application.Log(etInfo,cmd);
    AResponseInfo.ContentText:='Wapt Install launched<br><pre>'+
      StringsReplace(RunTask(cmd,ExitStatus),[#13#10,#13,#10],['<br>','<br>','<br>'],[rfReplaceAll])+'</pre>';
  end
  else
  begin
    St := TStringList.Create;
    try
      GetIpAddresses(St);
      IPS := St.Text;
    finally
      St.free;
    end;
    GetCpuInfo(CPUInfo);
    AResponseInfo.ContentText:=  (
      '<h1>System status</h1>'+
      'URI:'+ARequestInfo.URI+'<br>'+
      'AuthUsername:'+ARequestInfo.AuthUsername+'<br>'+
      'Document:'+ARequestInfo.Document+'<br>'+
      'Params:'+ARequestInfo.Params.Text+'<br>'+
      'User : '+TISGetUserName+'<br>'+
      'Machine: '+TISGetComputerName+'<br>'+
      'Domain: '+ GetWorkGroupName+'<br>'+
      'IP Addresses:'+IPS+'<br>'+
      'System: '+GetWindowsVersionString+' '+GetWindowsEditionString+' '+GetWindowsServicePackVersionString+'<br>'+
      'RAM: '+FormatFloat('###0 MB',GetTotalPhysicalMemory/1024/1024)+'<br>'+
      'CPU: '+CPUInfo.CpuName+'<br>'+
      'Memory Load: '+IntToStr(GetMemoryLoad)+'%');
  end;

  if AResponseInfo.ContentType='text/html' then
  begin
    AResponseInfo.ContentText := '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'+
         '<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">'+
         '<head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" />'+
         '<title>Wapt-get management</title></head>'+
         '<body>'+AResponseInfo.ContentText+'</body>';
  end;
  AResponseInfo.ResponseNo:=200;
  AResponseInfo.CharSet:='UTF-8';
end;

procedure TWaptDaemon.Timer1Timer(Sender: TObject);
begin

end;

function TWaptDaemon.TableHook(Data, FN: Utf8String): Utf8String;
begin
  FN := LowerCase(FN);
  if FN='package' then
    Result:='<a href="/install?package='+Data+'">'+Data+'</a>'
  else
    Result := Data;
end;


{$R *.lfm}


initialization
  RegisterDaemon;

end.

