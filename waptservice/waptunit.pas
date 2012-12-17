unit WaptUnit;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, DaemonApp,
  ExtCtrls, IdHTTPServer, IdCustomHTTPServer, IdContext, sqlite3conn, sqldb, db, Waptcommon,
  superobject;

type

  { TWaptDaemon }

  TWaptDaemon = class(TDaemon)
    IdHTTPServer1: TIdHTTPServer;
    Timer1: TTimer;

    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleStart(Sender: TCustomDaemon; var OK: Boolean);
    procedure IdHTTPServer1CommandGet(AContext: TIdContext;
      ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    procedure Timer1Timer(Sender: TObject);
  private
    FWAPTdb : TWAPTDB;
    { private declarations }
    inTimer:Boolean;
    function GetWaptDB: TWAPTDB;
    procedure SetWaptDB(AValue: TWAPTDB);
    function RepoTableHook(Data, FN: Utf8String): Utf8String;
    function StatusTableHook(Data, FN: Utf8String): Utf8String;
    function RegisterComputer:Boolean;
  public
    { public declarations }
    property WaptDB:TWAPTDB read GetWaptDB write SetWaptDB;
  end;

var
  WaptDaemon: TWaptDaemon;

implementation
uses JclSysInfo,IdSocketHandle,IdGlobal,process,StrUtils,idURI,tiscommon,soutils;

//  ,waptwmi,  Variants,Windows,ComObj;

procedure RegisterDaemon;
begin
  RegisterDaemonClass(TWaptDaemon)
end;

procedure HttpStartChunkedResponse(AResponseInfo:TIdHTTPResponseInfo;ContentType:String='';charset:String='');
begin
  AResponseInfo.TransferEncoding := 'chunked';
  if charset<>'' then
    AResponseInfo.CharSet:=charset;
  if ContentType<>'' then
    AResponseInfo.ContentType:= ContentType;
  AResponseInfo.WriteHeader;
end;

procedure HttpWriteChunk(AContext: TIdContext;Chunk:String;TextEncoding:TIdTextEncoding=Nil);
var
  l:Int64;
begin
  l := Length(Chunk);
  AContext.Connection.IOHandler.WriteLn(IntToHex(l,0));
  AContext.Connection.IOHandler.WriteLn(Chunk,TextEncoding);
end;

function RunTask(cmd: utf8string;var ExitStatus:integer;WorkingDir:utf8String=''): utf8string;
var
  AProcess: TProcess;
  Buffer,chunk: string;
  BytesAvailable: DWord;
  BytesRead:LongInt;
  StartTime : TDateTime;
  StartedOK:Boolean;
begin
    Result := '';
    AProcess := TProcess.Create(nil);
    try
      AProcess.CommandLine := cmd;
      if WorkingDir='' then
        AProcess.CurrentDirectory := ExtractFilePath(cmd);
      AProcess.Options := [poUsePipes,poNoConsole];
      AProcess.Execute;
      StartedOK:=True;
      StartTime:= Now;
      // Wait for Startup (5 sec)
      While not AProcess.Running do
      begin
        if (Now-StartTime>5/3600/24) then
        begin
          StartedOK:=False;
          Break;
        end;
        Sleep(200);
      end;

      While AProcess.Running do
      begin
        BytesAvailable := AProcess.Output.NumBytesAvailable;
        BytesRead := 0;
        while BytesAvailable>0 do
        begin
          SetLength(Buffer, BytesAvailable);
          BytesRead := AProcess.OutPut.Read(Buffer[1], BytesAvailable);
          Result := Result+copy(Buffer,1, BytesRead);
          BytesAvailable := AProcess.Output.NumBytesAvailable;
        end;
      end;
      ExitStatus:= AProcess.ExitStatus;
    finally
      AProcess.Free;
    end;
end;


function HttpRunTask(AHttpContext:TIdContext;AResponseInfo:TIdHTTPResponseInfo;cmd: utf8string;var ExitStatus:integer;WorkingDir:utf8String=''): utf8string;
var
  AProcess: TProcess;
  Buffer,chunk: string;
  BytesAvailable: DWord;
  BytesRead:LongInt;
  StartTime : TDateTime;
  StartedOK:Boolean;
begin
    Result := '';
    HttpStartChunkedResponse(AResponseInfo,'text/html','utf-8');
    AProcess := TProcess.Create(nil);
    try
      AProcess.CommandLine := cmd;
      if WorkingDir='' then
        AProcess.CurrentDirectory := ExtractFilePath(cmd);
      AProcess.Options := [poUsePipes,poNoConsole];
      AProcess.Execute;
      StartedOK:=True;
      StartTime:= Now;
      // Wait for Startup (5 sec)
      {While not AProcess.Running do
      begin
        if (Now-StartTime>5/3600/24) then
        begin
          StartedOK:=False;
          Break;
        end;
        Sleep(200);
      end;
      if not StartedOK then
        HttpWriteChunk(AHttpContext,'!!! Unable to start process within 5 sec '+'<br>',Nil);}

      repeat
        BytesAvailable := AProcess.Output.NumBytesAvailable;
        BytesRead := 0;
        if (BytesAvailable=0) and AProcess.Running then
          Sleep(200)
        else
        while BytesAvailable>0 do
        begin
          SetLength(Buffer, BytesAvailable);
          BytesRead := AProcess.OutPut.Read(Buffer[1], BytesAvailable);
          Result := Result+copy(Buffer,1, BytesRead);
          chunk := StringsReplace(copy(Buffer,1, BytesRead),[#13#10],['<br>'],[rfReplaceAll]);
          HttpWriteChunk(AHttpContext,Chunk,Nil);
          BytesAvailable := AProcess.Output.NumBytesAvailable;
        end;
      until not AProcess.Running;

      BytesAvailable := AProcess.Output.NumBytesAvailable;
      BytesRead := 0;
      while BytesAvailable>0 do
      begin
        SetLength(Buffer, BytesAvailable);
        BytesRead := AProcess.OutPut.Read(Buffer[1], BytesAvailable);
        Result := Result+copy(Buffer,1, BytesRead);
        chunk := StringsReplace(copy(Buffer,1, BytesRead),[#13#10],['<br>'],[rfReplaceAll]);
        HttpWriteChunk(AHttpContext,Chunk,Nil);
      end;

      ExitStatus:= AProcess.ExitStatus;
    finally
      HttpWriteChunk(AHttpContext,'');
      AProcess.Free;
    end;
end;


Type TFormatHook = Function(Data,FN:Utf8String):UTF8String of object;
{ TWaptDaemon }
function DatasetToHTMLtable(ds:TDataset;FormatHook: TFormatHook=Nil):String;
var
    i:integer;
begin
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

function LoadFile(FileName:Utf8String):Utf8String;
var
  f:TStringList;
begin
  try
    f := TStringList.Create;
    f.LoadFromFile(FileName);
    Result := f.Text;
  finally
    f.Free;
  end;
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


procedure TWaptDaemon.IdHTTPServer1CommandGet(AContext: TIdContext;
  ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
var
    ExitStatus:Integer;
    CPUInfo:TCpuInfo;
    St : TStringList;
    Cmd,IPS:String;
    i,f:integer;
    param,value,lst,UpgradeResult,SetupResult:String;
    so : ISuperObject;
    AQuery : TSQLQuery;
    filepath,template : Utf8String;
begin
  //Default type
  AResponseInfo.ContentType:='text/html';
  if LeftStr(ARequestInfo.URI,length('/static/'))='/static/' then
  begin
    filepath :=  ExtractFilePath(ParamStr(0))+ StringsReplace(ARequestInfo.URI,['/'],['\'],[rfReplaceAll]);
    if FileExists(FilePath) then
    begin
      AResponseInfo.ContentType:=AResponseInfo.HTTPServer.MIMETable.GetFileMIMEType(filepath);
      AResponseInfo.SmartServeFile(AContext,ARequestInfo,filepath);
    end
    else
      AResponseInfo.ResponseNo:=404;
  end
  else
  begin
    if ARequestInfo.URI='/status' then
    try
      AQuery := WaptDB.QueryCreate('select s.Package,s.Version,p.Version as RepoVersion,s.InstallDate,s.InstallStatus '+
                          ' from wapt_localstatus s'+
                          ' left join wapt_repo p on p.Package=s.Package '+
                          ' order by s.Package');
      AResponseInfo.ContentText:=DatasetToHTMLtable(AQuery,@StatusTableHook);
    finally
      AQuery.Free;
    end
    else
    if ARequestInfo.URI='/list' then
    try
      AQuery := WaptDB.QueryCreate('select * from wapt_repo order by Package');
      AResponseInfo.ContentText:=DatasetToHTMLtable(AQuery,@RepoTableHook );
    finally
      AQuery.Free;
    end
    else
    if ARequestInfo.URI='/waptupgrade' then
    begin
      HttpRunTask(AContext,AResponseInfo,WaptgetPath+' waptupgrade',ExitStatus);
      {UpgradeResult:=RunTask(WaptgetPath+' --upgrade',ExitStatus);
      AResponseInfo.ContentType:='application/json';
      SO:=TSuperObject.Create;
      with so.asObject do
      begin
        S['operation'] := 'upgrade';
        S['output'] := SplitLines(UpgradeResult);
        I['exitstatus'] := ExitStatus;
      end;
      AResponseInfo.ContentText:=so.AsJSon(True);}
    end
    else
    if ARequestInfo.URI='/dumpdb' then
    begin
      AResponseInfo.ContentType:='application/json';
      AResponseInfo.ContentText:=WaptDB.dumpdb.AsJSon(True);
    end
    else
    if ARequestInfo.URI='/upgrade' then
      HttpRunTask(AContext,AResponseInfo,WaptgetPath+' upgrade',ExitStatus)
    else
    if ARequestInfo.URI='/chunked' then
    begin
      HttpStartChunkedResponse(AResponseInfo,'application/json','UTF-8');
      for i := 0 to 10 do
      begin
        HttpWriteChunk(AContext,Utf8Encode('Chunk n°'+IntToStr(i)),TIdTextEncoding.UTF8);
        Sleep(1000);
      end;
      HttpWriteChunk(AContext,'');
    end
    else
    if ARequestInfo.URI='/update' then
      HttpRunTask(AContext,AResponseInfo,WaptgetPath+' update',ExitStatus)
    else
    if ARequestInfo.URI='/enable' then
      Timer1.Enabled:=True
    else
    if ARequestInfo.URI='/check_new' then
    begin
      AResponseInfo.ContentType:='application/json';
      AResponseInfo.ContentText:= '';
    end
    else
    if ARequestInfo.URI='/check_new' then
    begin
      AResponseInfo.ContentType:='application/json';
      AResponseInfo.ContentText:= '';
    end
    else
    if ARequestInfo.URI='/disable' then
      Timer1.Enabled:=False
    else
    if (ARequestInfo.URI='/sysinfo') or (ARequestInfo.URI='/register') then
    begin
      {if ARequestInfo.URI='/register' then
        httpGetString();}
      AResponseInfo.ContentType:='application/json';
      AResponseInfo.ContentText:= LocalSysinfo.AsJson(True);
    end
    else
    if (ARequestInfo.URI='/install') or (ARequestInfo.URI='/remove') or (ARequestInfo.URI='/showlog') then
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
      cmd := WaptgetPath;
      f:= ARequestInfo.Params.IndexOfName('force');
      if (f>=0) and (ARequestInfo.Params.ValueFromIndex[f]='yes') then
        cmd := cmd+' -f ';
      i:= ARequestInfo.Params.IndexOfName('package');
      if ARequestInfo.URI = '/install' then
        cmd := cmd+' install '+ARequestInfo.Params.ValueFromIndex[i]
      else
      if ARequestInfo.URI = '/remove' then
        cmd := cmd+' remove '+ARequestInfo.Params.ValueFromIndex[i]
      else
      if ARequestInfo.URI = '/showlog' then
        cmd := cmd+' showlog '+ARequestInfo.Params.ValueFromIndex[i];
      Application.Log(etInfo,cmd);
      HttpRunTask(AContext,AResponseInfo,cmd,ExitStatus)
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
      //AResponseInfo.ContentText:='tt';
      AResponseInfo.ContentText:= (
        '<h1>'+TISGetComputerName+' - System status</h1>'+
        'WAPT Server URL: '+GetWaptServerURL+'<br>'+
        'wapt-get version: '+ApplicationVersion(ExtractFilePath(ParamStr(0))+'\wapt-get.exe')+'<br>'+
        'waptservice version: '+ApplicationVersion(ExtractFilePath(ParamStr(0))+'\waptservice.exe')+'<br>'+
        'User : '+TISGetUserName+'<br>'+
        'Machine: '+TISGetComputerName+'<br>'+
        'Domain: '+ GetWorkGroupName+'<br>'+
        'IP Addresses:'+IPS+'<br>'+
        'System: '+GetWindowsVersionString+' '+GetWindowsEditionString+' '+GetWindowsServicePackVersionString+'<br>'+
        'RAM: '+FormatFloat('###0 MB',GetTotalPhysicalMemory/1024/1024)+'<br>'+
        'CPU: '+CPUInfo.CpuName+'<br>'+
        'Memory Load: '+IntToStr(GetMemoryLoad)+'%'+'<br>'+
        '<h1>Query info</h1>'+
        'URI:'+ARequestInfo.URI+'<br>'+
        'Document:'+ARequestInfo.Document+'<br>'+
        'Params:'+ARequestInfo.Params.Text+'<br>'+
        'AuthUsername:'+ARequestInfo.AuthUsername+'<br>'+
        '<h1>Service info</h1>'+
        'Check every:'+FormatFloat('#.##',Timer1.Interval/1000/60)+' min <br>'+
        'Active:'+BoolToStr(Timer1.Enabled,'Yes','No')+'<br>'
        );
    end;
    if AResponseInfo.ContentType='text/html' then
    begin
      Template := LoadFile(ExtractFilePath(ParamStr(0))+'\templates\layout.html');
      AResponseInfo.ContentText :=  StringsReplace(Template,['{% block content %}'],[AResponseInfo.ContentText],[rfReplaceALl]  );
      {      AResponseInfo.ContentText := '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'+
           '<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">'+
           '<head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" />'+
           '<title>Wapt-get management</title></head>'+
           '<body>'+AResponseInfo.ContentText+'</body>';}
    end;
    AResponseInfo.ResponseNo:=200;
    AResponseInfo.CharSet:='UTF-8';
  end;
  WaptDB := Nil;
end;

procedure TWaptDaemon.Timer1Timer(Sender: TObject);
begin
  try
    Timer1.Enabled:=False;
  finally
    Timer1.Enabled:=True;
  end;
end;

function TWaptDaemon.RepoTableHook(Data, FN: Utf8String): Utf8String;
begin
  FN := LowerCase(FN);
  if FN='package' then
    Result:='<a href="/install?package='+Data+'">'+Data+'</a>'
  else
    Result := Data;
end;

function TWaptDaemon.StatusTableHook(Data, FN: Utf8String): Utf8String;
begin
  FN := LowerCase(FN);
  if FN='package' then
    Result:='<a href="/showlog?package='+Data+'">'+Data+'</a>'
  else
    Result := Data;
end;


function TWaptDaemon.RegisterComputer: Boolean;
begin

end;


function TWaptDaemon.GetWaptDB: TWAPTDB;
begin
  if not Assigned(FWaptDB) then
  begin
    Fwaptdb := TWAPTDB.Create(WaptDBPath);
  end;
  Result := FWaptDB;
end;

procedure TWaptDaemon.SetWaptDB(AValue: TWAPTDB);
begin
  if FWaptDB=AValue then Exit;
  if Assigned(FWaptDB) then
    FreeAndNil(FWaptDB);
  FWaptDB:=AValue;
end;


{$R *.lfm}


initialization
  RegisterDaemon;

end.
