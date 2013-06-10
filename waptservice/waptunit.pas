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
  superobject,md5,syncobjs;

type

  { TWaptDaemon }

  TWaptDaemon = class(TDaemon)
    IdHTTPServer1: TIdHTTPServer;

    procedure DataModuleCreate(Sender: TObject);
    procedure DataModuleDestroy(Sender: TObject);
    procedure IdHTTPServer1CommandGet(AContext: TIdContext;
      ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
  private
    FWAPTdb : TWAPTDB;
    { private declarations }
    function GetWaptDB: TWAPTDB;
    function MD5PasswordForRepo(url: String): TMD5Digest;
    procedure ReadSettings;
    procedure SetWaptDB(AValue: TWAPTDB);
    function RepoTableHook(Dataset: TDataset; Data, FN: Utf8String): Utf8String;
    function StatusTableHook(Dataset: TDataset; Data, FN: Utf8String): Utf8String;
    function WaptRunstatus:ISuperObject;

  public
    { public declarations }
    BaseDir : String;

    waptupdate_task_period,
    waptupgrade_task_period:String;

    property WaptDB:TWAPTDB read GetWaptDB write SetWaptDB;
  end;

var
  WaptDaemon: TWaptDaemon;

implementation
uses LCLIntf,process,StrUtils,IdGlobal,idURI,tiscommon,tisstrings,soutils,
    IniFiles,UnitRedirect,windows;

procedure RegisterDaemon;
begin
  RegisterDaemonClass(TWaptDaemon)
end;

function RunTask(cmd: utf8string;var ExitStatus:integer;WorkingDir:utf8String=''): utf8string;
var
  AProcess: TProcess;
  Buffer: string;
  BytesAvailable: DWord;
  BytesRead:LongInt;
  StartTime : TDateTime;
begin
    Result := '';
    AProcess := TProcess.Create(nil);
    try
      AProcess.CommandLine := cmd;
      if WorkingDir='' then
        AProcess.CurrentDirectory := ExtractFilePath(cmd);
      AProcess.Options := [poUsePipes,poNoConsole];
      AProcess.Execute;
      StartTime:= Now;
      // Wait for Startup (5 sec)
      While not AProcess.Running do
      begin
        if (Now-StartTime>5/3600/24) then
          Break;
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
      section := 'global';
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
begin
  ini := TIniFile.Create(BaseDir + 'wapt-get.ini');
  try
    waptservice_port := ini.ReadInteger('global','service_port',waptservice_port);
    IdHTTPServer1.DefaultPort:= waptservice_port;

    waptupgrade_task_period := ini.ReadString('global','waptupgrade_task_period','');
    waptupdate_task_period := ini.ReadString('global','waptupdate_task_period','');

  finally
    ini.Free;
  end;
end;

procedure TWaptDaemon.DataModuleCreate(Sender: TObject);
begin
  Basedir := ExtractFilePath(ParamStr(0));
  SQLiteLibraryName:=BaseDir+'\DLLs\sqlite3.dll';
  readsettings;
  IdHTTPServer1.Active:=True;
end;

procedure TWaptDaemon.DataModuleDestroy(Sender: TObject);
begin
  WaptDB := Nil;
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
    Cmd:String;
    i,f:integer;
    auth_groups,sel : ISuperObject;
    AQuery : String;
    filepath,template : Utf8String;
    CmdOutput:Utf8String;
    auth_ok : Boolean;
    auth_user,last_error:String;
    groups : TDynStringArray;
    htok : Cardinal;
begin
  try
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
        AQuery := 'select s.package,s.version,s.install_date,s.install_status,"Remove" as Remove,'+
                            ' (select max(p.version) from wapt_package p where p.package=s.package) as repo_version,explicit_by as install_par'+
                            ' from wapt_localstatus s'+
                            ' order by s.package';
        AResponseInfo.ContentText:= WaptDB.QueryToHTMLtable(AQuery,@StatusTableHook);
      finally
      end
      else
      if ARequestInfo.URI='/list' then
      try
        AQuery := 'select "Install" as install,package,version,description,size from wapt_package where section<>"host" order by package,version';
        AResponseInfo.ContentText:=WaptDB.QueryToHTMLtable(AQuery,@RepoTableHook);
      finally
      end
      else
      if ARequestInfo.URI='/waptupgrade' then
        RunTask(WaptgetPath+' waptupgrade',ExitStatus)
      else
      if ARequestInfo.URI='/dumpdb' then
      begin
        AResponseInfo.ContentType:='application/json';
        AResponseInfo.ContentText:=String(WaptDB.dumpdb.AsJSon(True));
      end
      else
      if ARequestInfo.URI='/upgrade' then
      begin
        cmd := WaptgetPath;
        if ShellExecute(0, nil, pchar(cmd),pchar('-lwarning upgrade'), nil, 0) > 32 then
          CmdOutput:='OK : Process '+Cmd+' launched in background'
        else
          CmdOutput:='ERROR Launching process '+Cmd+' in background';
        AResponseInfo.ContentText:= '<h2>Output</h2>'+CmdOutput;
      end
      else
      if ARequestInfo.URI='/updatebg' then
      begin
        cmd := WaptgetPath;
        if ShellExecute(0, nil, pchar(cmd),pchar('-lwarning update'), nil, 0) > 32 then
          CmdOutput:='OK : Process '+Cmd+' launched in background'
        else
          CmdOutput:='ERROR Launching process '+Cmd+' in background';
        AResponseInfo.ContentText:= '<h2>Output</h2>'+CmdOutput;
      end
      else
      if ARequestInfo.URI='/update' then
      begin
        cmd := WaptgetPath+' -lwarning update';
        CmdOutput := Sto_RedirectedExecute(cmd);
        CmdOutput := cmd+'<br>'+StrUtils.StringsReplace(CmdOutput,[#13#10],['<br>'],[rfReplaceAll]);
        AResponseInfo.ContentText:= '<h2>Output</h2>'+CmdOutput;
      end
      else
      if ARequestInfo.URI='/clean' then
      begin
        cmd := WaptgetPath+' -lwarning clean';
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
        AResponseInfo.ContentType:='application/json';
        sel := WaptDB.Select('select * from wapt_params where name="last_update_status"');
        if (sel<>Nil) and (sel.AsArray.Length>0) then
          AResponseInfo.ContentText:= sel.AsArray[0].S['value']
        else
          AResponseInfo.ContentText:= '{"date": "", "running_tasks": [], "errors": [], "upgrades": []}';

      finally
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

        //Check Windows local authentication and group membership
        if not auth_ok and ARequestInfo.AuthExists and (ARequestInfo.AuthUsername<>'') and (ARequestInfo.AuthPassword<>'' ) and (GetDomainName <>'') then
        begin
          try
            htok := UserLogin(ARequestInfo.AuthUsername, ARequestInfo.AuthPassword,GetDomainName);
            try
              // check if in Domain Admins group
              auth_ok := True;
              groups := GetGroups(GetDNSDomain,ARequestInfo.AuthUsername);
              auth_groups := DynArr2SuperObject(groups);
            finally
              if htok>0 then
                closeHandle(htok);
            end;
          except
            on e:Exception do
            begin
              last_error:= e.Message;
              LogMessage('error Windows Login '+e.Message);
              auth_ok :=False;
            end;
          end;
        end;

        // Ask for user/Password if not yet authenticated
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

        if StrIsOneOf(ARequestInfo.URI,['/install','/remove']) and not StrIsOneOf('wapt-selfservice',groups) then
          CmdOutput:='Not authorized to install/remove this package, user "'+ARequestInfo.AuthUsername+'" is not a member of the group "'+'wapt-selfservice'+'"'
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
          CmdOutput := Sto_RedirectedExecute(cmd);
          CmdOutput := cmd+'<br>'+StrUtils.StringsReplace(CmdOutput,[#13#10],['<br>'],[rfReplaceAll]);
        end;
        AResponseInfo.ContentText:= '<h2>Output</h2>'+CmdOutput;
      end
      else
      begin
        //ReadSettings;
        AResponseInfo.ContentText:= (
          '<h1>'+tiscommon.GetComputerName+' - System status</h1>'+
          'WAPT Server URL: '+GetWaptServerURL+'<br>'+
          'wapt-get version: '+GetApplicationVersion(WaptgetPath)+'<br>'+
          'waptservice version: '+GetApplicationVersion(WaptservicePath)+'<br>'+'<br>'+
          'Current status: '+WaptRunstatus.S['value']+'<br>'+
          'User : '+tiscommon.GetUserName+'<br>'+
          'Machine: '+tiscommon.GetComputerName+'<br>'+
          'Workgroup: '+ GetWorkGroupName+'<br>'+
          'Domain: '+ GetDomainName+'<br>'+
          'DNS Server: '+ GetDNSServer+'<br>'+
          'DNS Domain: '+ GetDNSDomain+'<br>'+
          'IP Addresses:'+GetLocalIP+'<br>'+
          'Main WAPT Repository: '+ GetMainWaptRepo+'<br>'+
          'WAPT server: '+ GetWaptServerURL+'<br>'+
          'Configuration file: '+WaptIniFilename+'<br>'+
          '<h1>Query info</h1>'+
          'URI:'+ARequestInfo.URI+'<br>'+
          'Document:'+ARequestInfo.Document+'<br>'+
          'Params:'+ARequestInfo.Params.Text+'<br>'+
          'AuthUsername:'+ARequestInfo.AuthUsername+'<br>'+
          '<h1>Service info</h1>'+
          'Windows task Wapt-update period (minutes): '+waptupdate_task_period+' min <br>'+
          'Windows task Wapt-upgrade period (minutes): '+waptupgrade_task_period+' min <br>'
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
  finally
  end;
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

function TWaptDaemon.WaptRunstatus: ISuperObject;
begin
  Result := WaptDB.Select('select value,create_date from wapt_params where name=''runstatus''');
end;

function TWaptDaemon.GetWaptDB: TWAPTDB;
begin
  if not Assigned(FWaptDB) then
    Fwaptdb := TWAPTDB.Create(WaptDBPath);
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
