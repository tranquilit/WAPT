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

    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleStart(Sender: TCustomDaemon; var OK: Boolean);
    procedure IdHTTPServer1CommandGet(AContext: TIdContext;
      ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
  private
    FWAPTdb : TWAPTDB;
    { private declarations }
    inTimer:Boolean;
    function GetWaptDB: TWAPTDB;
    function MD5PasswordForRepo(url: String): TMD5Digest;
    procedure ReadSettings;
    procedure SetWaptDB(AValue: TWAPTDB);
    function RepoTableHook(Dataset: TDataset; Data, FN: Utf8String): Utf8String;
    function StatusTableHook(Dataset: TDataset; Data, FN: Utf8String): Utf8String;
    function RegisterComputer:Boolean;

    function WaptRunstatus:ISuperObject;


  public
    { public declarations }
    BaseDir : String;
    //Active directory server hostname for user authentication
    ldap_server : String;
    //Base DN for user and groups search
    ldap_basedn : String;
    //ADS Port number (636)
    ldap_port : String;

    waptupdate_task_period,
    waptupgrade_task_period:String;

    property WaptDB:TWAPTDB read GetWaptDB write SetWaptDB;
  end;

var
  WaptDaemon: TWaptDaemon;

implementation
uses LCLIntf,process,StrUtils,IdGlobal,IdSocketHandle,idURI,tiscommon,tisstrings,soutils,
    IniFiles,UnitRedirect,ldapsend,ldapauth,shellapi;

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


Type TFormatHook = Function(Dataset:TDataset;Data,FN:Utf8String):UTF8String of object;
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
          Result := Result + '<td>'+FormatHook(ds,ds.Fields[i].AsString,ds.Fields[i].FieldName)+'</td>'
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
  repos:TDynStringArray;
begin
  ini := TIniFile.Create(BaseDir + 'wapt-get.ini');
  try
    if url = '' then
      section := 'global'
    else
    begin
      repos := tisstrings.Split(ini.ReadString('global','repositories',''),',');

      //TODO
      section := url;
    end;
    md5str := ini.ReadString(section,'md5_password','5f4dcc3b5aa765d61d8327deb882cf99');
    MD5PasswordForRepo := hexstr2md5(md5str);
  finally
    ini.Free;
  end;
end;

procedure TWaptDaemon.ReadSettings;
var
  ini : TIniFile;
  basedn,ldaptcp : String;
  dnparts : TDynStringArray;
  i:integer;

begin
  ini := TIniFile.Create(BaseDir + 'wapt-get.ini');
  try
    waptservice_port := ini.ReadInteger('global','service_port',waptservice_port);
    IdHTTPServer1.DefaultPort:= waptservice_port;

    // par défaut, on considère que l'AD et sur le serveur DNS
    ldap_server:=ini.ReadString('global','ldap_server','');
    if ldap_server='' then
    try
      ldaptcp := GetLDAPServer;
      if ldaptcp<>'' then
        ldap_server := tisStrings.Split(ldaptcp,':')[0];
      ldap_port:=ini.ReadString('global','ldap_port','');
      if ldap_port='' then
        ldap_port := tisStrings.Split(ldaptcp,':')[1];
    except

    end
    else
      ldap_port:=ini.ReadString('global','ldap_port','636');

    // base de recherche pour LDAP basee sur le domaine DNS dc=toto,dc=local
    basedn := GetDNSDomain;
    dnparts := tisStrings.Split(basedn,'.');
    for i:=0 to Length(dnparts)-1 do
      dnparts[i] := 'dc='+dnparts[i];
    basedn := Join(',',dnparts);

    ldap_basedn:=ini.ReadString('global','ldap_basedn',basedn);
    // 636 : pour Active directory en SSL

    waptupgrade_task_period := ini.ReadString('global','waptupgrade_task_period','');
    waptupdate_task_period := ini.ReadString('global','waptupdate_task_period','');

  finally
    ini.Free;
  end;
end;

procedure TWaptDaemon.DataModuleCreate(Sender: TObject);
var
  sh : TIdSocketHandle;
  mainmodule : TStringList;
begin
  Basedir := ExtractFilePath(ParamStr(0));
  SQLiteLibraryName:=BaseDir+'\DLLs\sqlite3.dll';

  readsettings;

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
    param,value,lst,UpgradeResult:String;
    auth_groups : ISuperObject;
    AQuery : TSQLQuery;
    filepath,template : Utf8String;
    CmdOutput:Utf8String;
    htmloutput:Utf8String;
    ldap : TLdapSend;
    auth_ok : Boolean;
    auth_user,last_error:String;
    groups : TDynStringArray;
    htok : Cardinal;
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
      AQuery := WaptDB.QueryCreate('select s.package,s.version,s.install_date,s.install_status,"Remove" as Remove,'+
                          ' (select max(p.version) from wapt_package p where p.package=s.package) as repo_version,explicit_by as install_par'+
                          ' from wapt_localstatus s'+
                          ' order by s.package');
      AResponseInfo.ContentText:=DatasetToHTMLtable(AQuery,@StatusTableHook);
    finally
      AQuery.Free;
    end
    else
    if ARequestInfo.URI='/list' then
    try
      AQuery := WaptDB.QueryCreate('select "Install" as install,package,version,description,size from wapt_package where section<>"host" order by package,version');
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
    begin
    //HttpRunTask(AContext,AResponseInfo,WaptgetPath+' -e utf8 -lwarning upgrade',ExitStatus)
      cmd := WaptgetPath;
      if ShellExecute(0, nil, pchar(cmd),pchar('-lwarning upgrade'), nil, 0) > 32 then
      //CmdOutput := Sto_RedirectedExecute(cmd);
      //CmdOutput := cmd+'<br>'+StrUtils.StringsReplace(CmdOutput,[#13#10],['<br>'],[rfReplaceAll]);
        CmdOutput:='process '+Cmd+' launched in background'
      else
        CmdOutput:='ERROR launching process '+Cmd+' in background';

      AResponseInfo.ContentText:= '<h2>Output</h2>'+CmdOutput;
    end
    else
    if ARequestInfo.URI='/update' then
    begin
      //HttpRunTask(AContext,AResponseInfo,WaptgetPath+' -e utf8 -lwarning update',ExitStatus)
      cmd := WaptgetPath+' -lwarning update';
      CmdOutput := Sto_RedirectedExecute(cmd);
      CmdOutput := cmd+'<br>'+StrUtils.StringsReplace(CmdOutput,[#13#10],['<br>'],[rfReplaceAll]);
      AResponseInfo.ContentText:= '<h2>Output</h2>'+CmdOutput;
    end
    else
    if ARequestInfo.URI='/enable' then
    begin
      cmd := WaptgetPath+' -lcritical enable-tasks';
      Application.Log(etInfo,cmd);
      CmdOutput := Sto_RedirectedExecute(cmd);
      CmdOutput := StrUtils.StringsReplace(CmdOutput,[#13#10],['<br>'],[rfReplaceAll]);
      AResponseInfo.ContentText:= '<h2>Output</h2>'+CmdOutput;
    end
    else
    if ARequestInfo.URI='/runstatus' then
    begin
      AResponseInfo.ContentType:='application/json';
      AResponseInfo.ContentText:= WaptRunstatus.AsJSon;
    end
    else
    if ARequestInfo.URI='/checkupgrades' then
    try
      AQuery := WaptDB.QueryCreate('select * from wapt_params where name="last_update_status"');
      AQuery.Open;
      AResponseInfo.ContentType:='application/json';
      AResponseInfo.ContentText:= AQuery.FieldByName('value').AsString;
    finally
      AQuery.Free;
      WaptDB.db.Close;
    end
    else
    if ARequestInfo.URI='/disable' then
    begin
      cmd := WaptgetPath+' -lcritical disable-tasks';
      Application.Log(etInfo,cmd);
      CmdOutput := Sto_RedirectedExecute(cmd);
      CmdOutput := StrUtils.StringsReplace(CmdOutput,[#13#10],['<br>'],[rfReplaceAll]);
      AResponseInfo.ContentText:= '<h2>Output</h2>'+CmdOutput;
    end
    else
    if (ARequestInfo.URI='/sysinfo') or (ARequestInfo.URI='/register') then
    begin
      AResponseInfo.ContentType:='application/json';
      AResponseInfo.ContentText:= LocalSysinfo.AsJson(True);
    end
    else
    if (ARequestInfo.URI='/install') or (ARequestInfo.URI='/remove') or (ARequestInfo.URI='/showlog')  or (ARequestInfo.URI='/show') then
    begin
      auth_ok := False;
      auth_groups := Nil;

      // Check MD5 auth
      if not auth_ok then
      begin
        auth_ok := ARequestInfo.AuthExists and (ARequestInfo.AuthUsername = 'admin') and MD5Match(MD5String(ARequestInfo.AuthPassword),MD5PasswordForRepo(''));
        If auth_ok then
        begin
          SetLength(groups,1);
          groups[0] := 'wapt-selfservice';
        end;
      end;

      //Check Windows local auth
      if not auth_ok and ARequestInfo.AuthExists and (ARequestInfo.AuthUsername<>'') and (ARequestInfo.AuthPassword<>'' ) and (GetDomainName <>'') then
      begin
        try
          htok := UserLogin(ARequestInfo.AuthUsername, ARequestInfo.AuthPassword,GetDomainName);
          // check if in Domain Admins group
          auth_ok := True;
          groups := GetGroups(GetDNSDomain,ARequestInfo.AuthUsername);
          auth_groups := DynArr2SuperObject(groups);
        except
          on e:Exception do
          begin
            last_error:= e.Message;
            LogMessage('error Windows Login '+e.Message);
            auth_ok :=False;
          end;
        end;
      end;

      // Ask for user/Password
      if not auth_ok then
      begin
        AResponseInfo.ResponseNo := 401;
        AResponseInfo.ResponseText := 'Authorization required';
        AResponseInfo.ContentType := 'text/html';
        AResponseInfo.ContentText := '<html>Authentication required for Installation operations. error : '+last_error+'</html>';
        AResponseInfo.CustomHeaders.Values['WWW-Authenticate'] := 'Basic realm="WAPT-GET Authentication"';
        Exit;
      end
      else
        auth_user := ARequestInfo.AuthUsername;

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

      if auth_groups <> Nil then
        cmd := cmd+' -g "'+ChangeQuotes(auth_groups.AsJSon)+'"';

      if auth_user<>'' then
        cmd := cmd+' -U "'+auth_user+'"';

      if StrIsOneOf(ARequestInfo.URI,['/install','/remove']) and
        not StrIsOneOf('wapt-selfservice',groups) then
      begin
        CmdOutput:='Not authorized to install/remove this package, user "'+ARequestInfo.AuthUsername+'" is not member of "'+'wapt-selfservice'+'"';
      end
      else
      begin
        i:= ARequestInfo.Params.IndexOfName('package');
        if ARequestInfo.URI = '/install' then
          cmd := cmd+' install '+ARequestInfo.Params.ValueFromIndex[i]
        else
        if ARequestInfo.URI = '/remove' then
          cmd := cmd+' remove '+ARequestInfo.Params.ValueFromIndex[i]
        else
        if ARequestInfo.URI = '/showlog' then
          cmd := cmd+' showlog '+ARequestInfo.Params.ValueFromIndex[i];
        if ARequestInfo.URI = '/show' then
          cmd := cmd+' show '+ARequestInfo.Params.ValueFromIndex[i];
        Application.Log(etInfo,cmd);
        //HttpRunTask(AContext,AResponseInfo,cmd,ExitStatus)
        CmdOutput := Sto_RedirectedExecute(cmd);
        CmdOutput := cmd+'<br>'+StrUtils.StringsReplace(CmdOutput,[#13#10],['<br>'],[rfReplaceAll]);
        //CmdError:=AnsiToUtf8(StrUtils.StringsReplace(CmdError,[#13#10],['<br>'],[rfReplaceAll]));
      end;
      AResponseInfo.ContentText:= '<h2>Output</h2>'+CmdOutput;
      //+'<h2>Errors</h2>'+CmdError;
      //AResponseInfo.ContentText:= RunTask(cmd,ExitStatus)
    end
    else
    begin
      ReadSettings;
      AResponseInfo.ContentText:= (
        '<h1>'+GetComputerName+' - System status</h1>'+
        'WAPT Server URL: '+GetWaptServerURL+'<br>'+
        'wapt-get version: '+GetApplicationVersion(WaptgetPath)+'<br>'+
        'waptservice version: '+GetApplicationVersion(WaptservicePath)+'<br>'+'<br>'+
        'Current status: '+WaptRunstatus.S['value']+'<br>'+
        'User : '+GetUserName+'<br>'+
        'Machine: '+GetComputerName+'<br>'+
        'Workgroup: '+ GetWorkGroupName+'<br>'+
        'Domain: '+ GetDomainName+'<br>'+
        'DNS Server: '+ GetDNSServer+'<br>'+
        'DNS Domain: '+ GetDNSDomain+'<br>'+
        'IP Addresses:'+GetLocalIP+'<br>'+
        'LDAP Server (ADS):'+ldap_server+'<br>'+
        'LDAP port:'+ldap_port+'<br>'+
        'LDAP base DN:'+ldap_basedn+'<br>'+
        'Main WAPT Repository: '+ GetMainWaptRepo+'<br>'+
        'WAPT server: '+ GetWaptServerURL+'<br>'+
        'Configuration file: '+WaptIniFilename+'<br>'+
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
        //'Check every:'+FormatFloat('#.##',Timer1.Interval/1000/60)+' min <br>'+
        //'Active:'+BoolToStr(Timer1.Enabled,'Yes','No')+'<br>'+
        'Windows task Wapt-update period (minutes): '+waptupdate_task_period+' min <br>'+
        'Windows task Wapt-upgrade period (minutes): '+waptupgrade_task_period+' min <br>'

        //+'Python engine:'+APythonEngine.EvalStringAsStr('mywapt.update()')
        );
    end;
    if AResponseInfo.ContentType='text/html' then
    begin
      AResponseInfo.ContentText :=  AResponseInfo.ContentText;
      Template := LoadFile(ExtractFilePath(ParamStr(0))+'\templates\layout.html');
      AResponseInfo.ContentText :=  strutils.StringsReplace(Template,['{% block content %}'],[AResponseInfo.ContentText],[rfReplaceALl]  );
    end;
    AResponseInfo.ResponseNo:=200;
    AResponseInfo.CharSet:='UTF-8';
  end;
  WaptDB := Nil;
end;

function TWaptDaemon.RepoTableHook(Dataset:TDataset;Data, FN: Utf8String): Utf8String;
var
  package:String;
begin
  FN := LowerCase(FN);
  package := '"'+Dataset['package']+'(='+Dataset['version']+')"';
  if FN='package' then
    Result:='<a href="'+TIdURI.ParamsEncode('/show?package='+package)+'">'+Data+'</a>'
  else
  if FN='install' then
    Result:='<a class=action href="javascript: if (confirm(''Confirm the installation of '+Dataset['package']+' ?'')) { window.location.href='''+
      TIdURI.ParamsEncode('/install?package='+package)+''' } else { void('''') }">'+Data+'</a>'
  else
    Result := Data;
end;

function TWaptDaemon.StatusTableHook(Dataset:TDataset;Data, FN: Utf8String): Utf8String;
begin
  FN := LowerCase(FN);
  if FN='package' then
    Result:='<a href="/showlog?package='+Data+'">'+Data+'</a>'
  else
  if FN='remove' then
    Result:='<a class=action href="javascript: if (confirm(''Confirm the removal of '+Dataset['package']+' ?'')) { window.location.href=''/remove?package='+Dataset['package']+''' } else { void('''') }">'+Data+'</a>'
  else
  if FN='install_date' then
    Result:=copy(data,1,10)+' '+copy(data,12,5)
  else
    Result := Data;
end;

function TWaptDaemon.RegisterComputer: Boolean;
begin
  //httpPostData();
end;

function TWaptDaemon.WaptRunstatus: ISuperObject;
var
  AQuery: TSQLQuery;
begin
  try
    AQuery := WaptDB.QueryCreate('select value,create_date from wapt_params where name=''runstatus''');
    Result := Dataset2SO(AQuery,False);
  finally
    AQuery.Free;
    WaptDB.db.Close;
  end
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
