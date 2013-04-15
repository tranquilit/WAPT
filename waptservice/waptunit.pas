unit WaptUnit;
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
  Classes, SysUtils, FileUtil, DaemonApp,
  ExtCtrls, IdHTTPServer, IdCustomHTTPServer, IdContext, sqlite3conn, sqldb, db, Waptcommon,
  superobject,md5;

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
    function MD5PasswordForRepo(url: String): TMD5Digest;
    procedure SetWaptDB(AValue: TWAPTDB);
    function RepoTableHook(Data, FN: Utf8String): Utf8String;
    function StatusTableHook(Data, FN: Utf8String): Utf8String;
    function RegisterComputer:Boolean;
  public
    { public declarations }
    BaseDir : String;
    property WaptDB:TWAPTDB read GetWaptDB write SetWaptDB;
  end;

var
  WaptDaemon: TWaptDaemon;

implementation
uses process,StrUtils,IdGlobal,IdSocketHandle,idURI,tiscommon,soutils,IniFiles,UnitRedirect;

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
          chunk := StrUtils.StringsReplace(copy(Buffer,1, BytesRead),[#13#10],['<br>'],[rfReplaceAll]);
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
        chunk := StrUtils.StringsReplace(copy(Buffer,1, BytesRead),[#13#10],['<br>'],[rfReplaceAll]);
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

function hexstr2md5(hexstr:String):TMD5Digest;
var
  i:integer;
begin
  for i:=0 to 15 do
     result[i]:=Hex2Dec(copy(hexstr,1+i*2,2));
end;

function TWaptDaemon.MD5PasswordForRepo(url:String):TMD5Digest;
var
  md5str,section : String;
  ini : TIniFile;
  i:integer;
  repos:Array of String;
begin
  ini := TIniFile.Create(BaseDir + 'wapt-get.ini');
  try
    if url = '' then
      section := 'global'
    else
    begin
      //TODO
      section := url;
    end;
    md5str := ini.ReadString(section,'md5_password','5f4dcc3b5aa765d61d8327deb882cf99');
    MD5PasswordForRepo := hexstr2md5(md5str);
  finally
    ini.Free;
  end;
end;

procedure TWaptDaemon.DataModuleCreate(Sender: TObject);
var
  sh : TIdSocketHandle;
  ini : TIniFile;
  md5str : String;
  mainmodule : TStringList;
begin
  Basedir := ExtractFilePath(ParamStr(0));
  SQLiteLibraryName:=BaseDir+'\DLLs\sqlite3.dll';
  ini := TIniFile.Create(BaseDir + 'wapt-get.ini');
  try
    waptservice_port := ini.ReadInteger('global','service_port',waptservice_port);
    IdHTTPServer1.DefaultPort:= waptservice_port;
    //default md5 of 'password'
  finally
    ini.Free;
  end;

  sh := IdHTTPServer1.Bindings.Add;
  sh.IP:='127.0.0.1';
  sh.Port:=waptservice_port;
  IdHTTPServer1.Active:=True;

  {with ApythonEngine do
  begin
    DllName := 'python27.dll';
    RegVersion := '2.7';
    UseLastKnownVersion := False;
    Py_SetProgramName(PAnsiChar(ParamStr(0)));
  end;

  // Load main python application
  try
    MainModule:=TStringList.Create;
    MainModule.LoadFromFile(ExtractFilePath(ParamStr(0))+'waptserviceinit.py');
    APythonEngine.ExecStrings(MainModule);
  finally
    MainModule.Free;
  end;}
end;

function ChangeQuotes(s:String):String;
var
  i:integer;
begin
  result := s;
  for i:=1 to Length(result) do
    if result[i]='"' then result[i] := '''';
end;

procedure TWaptDaemon.IdHTTPServer1CommandGet(AContext: TIdContext;
  ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
var
    ExitStatus:Integer;
    St : TStringList;
    Cmd,IPS:String;
    i,f:integer;
    param,value,lst,UpgradeResult,SetupResult:String;
    so : ISuperObject;
    AQuery : TSQLQuery;
    filepath,template : Utf8String;
    CmdOutput,CmdError:AnsiString;
    htmloutput:Utf8String;
begin
  //Default type
  AResponseInfo.ContentType:='text/html';
  if LeftStr(ARequestInfo.URI,length('/static/'))='/static/' then
  begin
    filepath :=  ExtractFilePath(ParamStr(0))+ StrUtils.StringsReplace(ARequestInfo.URI,['/'],['\'],[rfReplaceAll]);
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
      AQuery := WaptDB.QueryCreate('select s.package,s.version,p.version as repo_version,s.install_date,s.install_status '+
                          ' from wapt_localstatus s'+
                          ' left join wapt_package p on p.package=s.package and p.version=s.version'+
                          ' order by s.package');
      AResponseInfo.ContentText:=DatasetToHTMLtable(AQuery,@StatusTableHook);
    finally
      AQuery.Free;
    end
    else
    if ARequestInfo.URI='/list' then
    try
      AQuery := WaptDB.QueryCreate('select package,version,description,size from wapt_package order by package,version');
      AResponseInfo.ContentText:=DatasetToHTMLtable(AQuery,@RepoTableHook );
    finally
      AQuery.Free;
    end
    else
    if ARequestInfo.URI='/waptupgrade' then
    begin
      RunTask(WaptgetPath+' waptupgrade',ExitStatus);
      //HttpRunTask(AContext,AResponseInfo,WaptgetPath+' waptupgrade',ExitStatus);
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
      HttpRunTask(AContext,AResponseInfo,WaptgetPath+' -lcritical upgrade',ExitStatus)
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
      HttpRunTask(AContext,AResponseInfo,WaptgetPath+' -lcritical update',ExitStatus)
    else
    if ARequestInfo.URI='/enable' then
      Timer1.Enabled:=True
    else
    if ARequestInfo.URI='/checkupgrades' then
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
      if not ARequestInfo.AuthExists or (ARequestInfo.AuthUsername <> 'admin') or
        not MD5Match(MD5String(ARequestInfo.AuthPassword),MD5PasswordForRepo('')) then
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
      //cmd := cmd+' --encoding=utf8 ';

      f:= ARequestInfo.Params.IndexOfName('force');
      if (f>=0) and (ARequestInfo.Params.ValueFromIndex[f]='yes') then
        cmd := cmd+' -f ';

      f:= ARequestInfo.Params.IndexOfName('params');
      if (f>=0) then
        cmd := cmd+' -p "'+ChangeQuotes(ARequestInfo.Params.ValueFromIndex[f])+'"';

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
      //HttpRunTask(AContext,AResponseInfo,cmd,ExitStatus)
      Sto_RedirectedExecute(cmd,CmdOutput,CmdError);
      CmdOutput := StrUtils.StringsReplace(CmdOutput,[#13#10],['<br>'],[rfReplaceAll]);
      //CmdError:=AnsiToUtf8(StrUtils.StringsReplace(CmdError,[#13#10],['<br>'],[rfReplaceAll]));
      AResponseInfo.ContentText:= '<h2>Output</h2>'+CmdOutput;
      //+'<h2>Errors</h2>'+CmdError;
      //AResponseInfo.ContentText:= RunTask(cmd,ExitStatus)
    end
    else
    begin
      AResponseInfo.ContentText:= (
        '<h1>'+GetComputerName+' - System status</h1>'+
        'WAPT Server URL: '+GetWaptServerURL+'<br>'+
        'wapt-get version: '+GetApplicationVersion(WaptgetPath)+'<br>'+
        'waptservice version: '+GetApplicationVersion(WaptservicePath)+'<br>'+
        'User : '+GetUserName+'<br>'+
        'Machine: '+GetComputerName+'<br>'+
        'Workgroup: '+ GetWorkGroupName+'<br>'+
        'Domain: '+ GetDomainName+'<br>'+
        'DNS Server: '+ GetDNSServer+'<br>'+
        'DNS Domain: '+ GetDNSDomain+'<br>'+
        'IP Addresses:'+GetLocalIP+'<br>'+
        'Main WAPT Repository: '+ GetMainWaptRepo+'<br>'+
        'WAPT server: '+ GetWaptServerURL+'<br>'+
        //'System: '+GetWindowsVersionString+' '+GetWindowsEditionString+' '+GetWindowsServicePackVersionString+'<br>'+
        //'RAM: '+FormatFloat('###0 MB',GetTotalPhysicalMemory/1024/1024)+'<br>'+
        //'CPU: '+CPUInfo.CpuName+'<br>'+
        //'Memory Load: '+IntToStr(GetMemoryLoad)+'%'+'<br>'+
        '<h1>Query info</h1>'+
        'URI:'+ARequestInfo.URI+'<br>'+
        'Document:'+ARequestInfo.Document+'<br>'+
        'Params:'+ARequestInfo.Params.Text+'<br>'+
        'AuthUsername:'+ARequestInfo.AuthUsername+'<br>'+
        '<h1>Service info</h1>'+
        'Check every:'+FormatFloat('#.##',Timer1.Interval/1000/60)+' min <br>'+
        'Active:'+BoolToStr(Timer1.Enabled,'Yes','No')+'<br>'
        //+'Python engine:'+APythonEngine.EvalStringAsStr('mywapt.update()')
        );
    end;
    if AResponseInfo.ContentType='text/html' then
    begin
      Template := LoadFile(ExtractFilePath(ParamStr(0))+'\templates\layout.html');
      //AResponseInfo.ContentText:= AnsiToUtf8(AResponseInfo.ContentText);
      AResponseInfo.ContentText :=  strutils.StringsReplace(Template,['{% block content %}'],[AResponseInfo.ContentText],[rfReplaceALl]  );
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
  //httpPostData();
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
