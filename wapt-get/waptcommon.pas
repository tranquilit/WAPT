unit waptcommon;

{$mode objfpc}{$H+}
interface
  uses
     interfaces,Classes, SysUtils,windows,
     WinInet,zipper,registry,strutils,FileUtil,SuperObject,DB,sqldb,sqlite3conn,Process;

  const
    waptservice_port = 8088;

  Function  FindWaptRepo:String;
  Function  GetWaptServerURL:String;

  Function  Wget(const fileURL, DestFileName: Utf8String): boolean;
  Function  Wget_try(const fileURL: Utf8String): boolean;

  function httpGetString(url: string): Utf8String;


  Procedure UnzipFile(ZipFilePath,OutputPath:Utf8String);
  Procedure AddToUserPath(APath:Utf8String);
  procedure AddToSystemPath(APath:Utf8String);
  procedure UpdateCurrentApplication(fromURL:String;Restart:Boolean;restartparam:Utf8String);
  function  ApplicationVersion(FileName:Utf8String=''): Utf8String;

  function GetApplicationName:Utf8String;
  function GetPersonalFolder:Utf8String;
  function GetAppdataFolder:Utf8String;

  function TISAppuserinipath:Utf8String;
  function TISGetComputerName : Utf8String;
  function TISGetUserName : Utf8String;

  function SortableVersion(VersionString:String):String;

  function DateTime2StrUTC(ADatetime:TDateTime):String;
  function StrUTC2DateTime(AUTCStrDatetime:String):TDateTime;

  function StringList2SuperObject(St:TStringList):ISuperObject;
  function SplitLines(St:String):ISuperObject;

  function Dataset2SO(DS:TDataset;AllRecords:Boolean=True):ISuperObject;
  procedure SO2Dataset(SO:ISuperObject;DS:TDataset;ExcludedFields:Array of String);


  type LogLevel=(DEBUG, INFO, WARNING, ERROR, CRITICAL);
  procedure Logger(Msg:String;level:LogLevel=WARNING);

  Const
    SECURITY_NT_AUTHORITY: TSIDIdentifierAuthority = (Value: (0, 0, 0, 0, 0, 5));
    SECURITY_BUILTIN_DOMAIN_RID = $00000020;
    DOMAIN_ALIAS_RID_ADMINS     = $00000220;
    DOMAIN_ALIAS_RID_USERS      = $00000221;
    DOMAIN_ALIAS_RID_GUESTS     = $00000222;
    DOMAIN_ALIAS_RID_POWER_USERS= $00000223;

  function UserInGroup(Group :DWORD) : Boolean;
  function IsAdminLoggedOn: Boolean;

  function ProcessExists(ExeFileName: string): boolean;
  function KillTask(ExeFileName: string): integer;
  function CheckOpenPort(dwPort : Word; ipAddressStr:AnsiString;timeout:integer=5):boolean;
  function GetIPFromHost(const HostName: string): string;

  function WaptgetPath: Utf8String;
  function WaptDBPath: Utf8String;

  function RunTask(cmd: utf8string;var ExitStatus:integer;WorkingDir:utf8String=''): utf8string;


  function GetSystemProductName: String;
  function GetSystemManufacturer: String;
  function GetBIOSVendor: String;
  function GetBIOSVersion: String;

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

var
  loghook : procedure(logmsg:String) of object;

const
    currentLogLevel:LogLevel=WARNING;

implementation

uses winsock,JwaTlHelp32,JCLSysInfo,shlobj,JCLShell,JCLStrings,JCLRegistry;

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


function IsAdminLoggedOn: Boolean;
{ Returns True if the logged-on user is a member of the Administrators local
  group. Always returns True on Windows 9x/Me. }
const
  DOMAIN_ALIAS_RID_ADMINS = $00000220;
begin
  Result := UserInGroup(DOMAIN_ALIAS_RID_ADMINS);
end;

function wget(const fileURL, DestFileName: Utf8String): boolean;
 const
   BufferSize = 1024;
 var
   hSession, hURL: HInternet;
   Buffer: array[1..BufferSize] of Byte;
   BufferLen: DWORD;
   f: File;
   sAppName: Utf8string;
   Size: Integer;
   dwindex: cardinal;
   dwcode : array[1..20] of char;
   dwCodeLen : DWORD;
   dwNumber: DWORD;
   res : PChar;

begin
  result := false;
  sAppName := ExtractFileName(ParamStr(0)) ;
  hSession := InternetOpenW(PWideChar(UTF8Decode(sAppName)), INTERNET_OPEN_TYPE_PRECONFIG, nil, nil, 0) ;
  try
    hURL := InternetOpenUrlW(hSession, PWideChar(UTF8Decode(fileURL)), nil, 0, INTERNET_FLAG_RELOAD+INTERNET_FLAG_PRAGMA_NOCACHE+INTERNET_FLAG_KEEP_CONNECTION, 0) ;
    if assigned(hURL) then
    try
      dwIndex  := 0;
      dwCodeLen := 10;
      HttpQueryInfo(hURL, HTTP_QUERY_STATUS_CODE, @dwcode, dwcodeLen, dwIndex);
      res := pchar(@dwcode);
      dwNumber := sizeof(Buffer)-1;
      if (res ='200') or (res ='302') then
      begin
        Size:=0;
        AssignFile(f, UTF8Decode(DestFileName)) ;
        Rewrite(f,1) ;
        repeat
          BufferLen:= 0;
          if InternetReadFile(hURL, @Buffer, SizeOf(Buffer), BufferLen) then
          begin
            inc(Size,BufferLen);
            BlockWrite(f, Buffer, BufferLen)
          end;
        until BufferLen = 0;
        CloseFile(f) ;
        result := (Size>0);
      end
      else
        raise Exception.Create('Unable to download: "'+fileURL+'", HTTP Status:'+res);
    finally
      InternetCloseHandle(hURL)
    end
  finally
    InternetCloseHandle(hSession)
  end
end;

function wget_try(const fileURL: Utf8String): boolean;
 const
   BufferSize = 1024;
 var
   hSession, hURL: HInternet;
   Buffer: array[1..BufferSize] of Byte;
   BufferLen: DWORD;
   sAppName: Utf8string;
   dwindex: cardinal;
   dwcode : array[1..20] of char;
   dwCodeLen : DWORD;
   dwNumber: DWORD;
   res : PChar;

begin
  result := false;
  sAppName := ExtractFileName(ParamStr(0)) ;
  hSession := InternetOpenW(PWideChar(UTF8Decode(sAppName)), INTERNET_OPEN_TYPE_PRECONFIG, nil, nil, 0) ;
  try
    hURL := InternetOpenUrlW(hSession, PWideChar(UTF8Decode(fileURL)), nil, 0, INTERNET_FLAG_RELOAD+INTERNET_FLAG_PRAGMA_NOCACHE+INTERNET_FLAG_KEEP_CONNECTION , 0) ;
    if assigned(hURL) then
    try
      dwIndex  := 0;
      dwCodeLen := 10;
      HttpQueryInfo(hURL, HTTP_QUERY_STATUS_CODE, @dwcode, dwcodeLen, dwIndex);
      res := pchar(@dwcode);
      dwNumber := sizeof(Buffer)-1;
      result :=  (res ='200') or (res ='302');
    finally
      InternetCloseHandle(hURL)
    end
  finally
    InternetCloseHandle(hSession)
  end
end;

function httpGetString(
    url: string): Utf8String;
var
  GlobalhInet,hFile: HINTERNET;
  localFile: File;
  buffer: array[1..1024] of byte;
  bytesRead: DWORD;
  pos:integer;
  dwindex,dwcodelen,dwread,dwNumber: cardinal;
  dwcode : array[1..20] of char;
  res    : pchar;

begin
  result := '';
  //if not Assigned(GlobalhInet) then
    GlobalhInet := InternetOpen('wapt',
      INTERNET_OPEN_TYPE_PRECONFIG,nil,nil,0);
  hFile := InternetOpenURL(GlobalhInet,PChar(url),nil,0,
    INTERNET_FLAG_IGNORE_CERT_CN_INVALID or INTERNET_FLAG_NO_CACHE_WRITE
    or INTERNET_FLAG_PRAGMA_NOCACHE or INTERNET_FLAG_RELOAD+INTERNET_FLAG_KEEP_CONNECTION ,0);
  if Assigned(hFile) then
  try
    dwIndex  := 0;
    dwCodeLen := 10;
    HttpQueryInfo(hFile, HTTP_QUERY_STATUS_CODE, @dwcode, dwcodeLen, dwIndex);
    res := pchar(@dwcode);
    dwNumber := sizeof(Buffer)-1;
    if (res ='200') or (res ='302') then
    begin
      Result:='';
      pos:=1;
      repeat
        FillChar(buffer,SizeOf(buffer),0);
        InternetReadFile(hFile,@buffer,SizeOf(buffer),bytesRead);
        SetLength(Result,Length(result)+bytesRead+1);
        Move(Buffer,Result[pos],bytesRead);
        inc(pos,bytesRead);
      until bytesRead = 0;
    end
    else
       raise Exception.Create('Unable to download: "'+URL+'", HTTP Status:'+res);
  finally
    InternetCloseHandle(hFile);
  end;
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

function CheckTokenMembership(TokenHandle: THandle; SidToCheck: PSID; var IsMember: BOOL): BOOL; stdcall; external advapi32;

function UserInGroup(Group :DWORD) : Boolean;
var
  pIdentifierAuthority :TSIDIdentifierAuthority;
  pSid : Windows.PSID;
  IsMember    : BOOL;
begin
  pIdentifierAuthority := SECURITY_NT_AUTHORITY;
  Result := AllocateAndInitializeSid(pIdentifierAuthority,2, SECURITY_BUILTIN_DOMAIN_RID, Group, 0, 0, 0, 0, 0, 0, pSid);
  try
    if Result then
      if not CheckTokenMembership(0, pSid, IsMember) then //passing 0 means which the function will be use the token of the calling thread.
         Result:= False
      else
         Result:=IsMember;
  finally
     FreeSid(pSid);
  end;
end;

//Unzip file to path, and return list of files as a string
Procedure UnzipFile(ZipFilePath,OutputPath:Utf8String);
var
  UnZipper: TUnZipper;
begin
  UnZipper := TUnZipper.Create;
  try
    UnZipper.FileName := ZipFilePath;
    UnZipper.OutputPath := OutputPath;
    UnZipper.Examine;
    UnZipper.UnZipAllFiles;
  finally
    UnZipper.Free;
  end;
end;

procedure AddToUserPath(APath:Utf8String);
var
  SystemPath : Utf8String;
begin
  with TRegistry.Create do
  try
    //RootKey:=HKEY_LOCAL_MACHINE;
    OpenKey('Environment',False);
    SystemPath:=ReadString('PATH');
    if pos(LowerCase(APath),LowerCase(SystemPath))=0 then
    begin
      if RightStr(SystemPath,1)<>';' then SystemPath:=SystemPath+';';
      SystemPath:=SystemPath+APath;
      if RightStr(SystemPath,1)<>';' then SystemPath:=SystemPath+';';
      WriteString('PATH',SystemPath);
    end;
  finally
    Free;
  end;
end;

procedure AddToSystemPath(APath:Utf8String);
var
  SystemPath : Utf8String;
  aresult:LongWord;
begin
  with TRegistry.Create do
  try
    RootKey:=HKEY_LOCAL_MACHINE;
    OpenKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment',False);
    SystemPath:=ReadString('Path');
    if pos(LowerCase(APath),LowerCase(SystemPath))=0 then
    begin
      if RightStr(SystemPath,1)<>';' then SystemPath:=SystemPath+';';
      SystemPath:=SystemPath+APath;
      if RightStr(SystemPath,1)<>';' then SystemPath:=SystemPath+';';
      WriteExpandString('Path',SystemPath);
      Windows.SendMessageTimeout(HWND_BROADCAST,WM_SETTINGCHANGE,0,Longint(PChar('Environment')),0,1000,aresult);
    end;
  finally
    Free;
  end;
end;

procedure UpdateCurrentApplication(fromURL:String;restart:Boolean;restartparam:Utf8String);
var
  bat: TextFile;
  tempdir,tempfn,updateBatch,fn,zipfn,version,destdir : Utf8String;
  files:TStringList;
  UnZipper: TUnZipper;
  i:integer;
begin
  Files := TStringList.Create;
  try
    Logger('Updating current application in place...');
    tempdir := GetTempFilename(GetTempDir,'waptget');
    fn :=ExtractFileName(ParamStr(0));
    destdir := ExtractFileDir(ParamStr(0));

    tempfn := tempdir+'\'+fn;
    mkdir(tempdir);
    Logger('Getting new file from: '+fromURL+' into '+tempfn);
    try
      wget(fromURL,tempfn);
      version := ApplicationVersion(tempfn);
      if version='' then
        raise Exception.create('no version information in downloaded file.');
      Logger(' got '+fn+' version: '+version);
      Files.Add(fn);
    except
      //trying to get a zip file instead (exe files blocked by proxy ...)
      zipfn:=tempdir+'\'+ChangeFileExt(fn,'.zip');
      wget(ChangeFileExt(fromURL,'.zip'),zipfn);
      Logger('  unzipping file '+zipfn);
      UnZipper := TUnZipper.Create;
      try
        UnZipper.FileName := zipfn;
        UnZipper.OutputPath := tempdir;
        UnZipper.Examine;
        UnZipper.UnZipAllFiles;
        for i := 0 to UnZipper.Entries.count-1 do
          if not UnZipper.Entries[i].IsDirectory then
            Files.Add(StringReplace(UnZipper.Entries[i].DiskFileName,'/','\',[rfReplaceAll]));
      finally
        UnZipper.Free;
      end;

      version := ApplicationVersion(tempfn);
      if version='' then
        raise Exception.create('no version information in downloaded exe file.');
      Logger(' got '+fn+' version: '+version);
    end;

    if FileExists(tempfn) and (FileSize(tempfn)>0) then
    begin
      // small batch to replace current running application
      updatebatch := tempdir + '\update.bat';
      AssignFile(bat,updateBatch);
      Rewrite(bat);
      try
        Logger(' Creating update batch file '+updateBatch);
        // wait for program to terminate..
        Writeln(bat,'timeout /T 2');
        Writeln(bat,'taskkill /im '+fn+' /f');
        for i:= 0 to files.Count-1 do
        begin
          // be sure to have target directory
          if not DirectoryExists(ExtractFileDir(IncludeTrailingPathDelimiter(destdir)+files[i])) then
            MkDir(ExtractFileDir(IncludeTrailingPathDelimiter(destdir)+files[i]));
          Writeln(bat,'copy "'+IncludeTrailingPathDelimiter(tempdir)+files[i]+'" "'+IncludeTrailingPathDelimiter(destdir)+files[i]+'"');
        end;
        Writeln(bat,'cd ..');
        if restart then
          Writeln(bat,'start "" "'+ParamStr(0)+'" '+restartparam);
        Writeln(bat,'rmdir /s /q "'+tempdir+'"');
      finally
        CloseFile(bat)
      end;
      Logger(' Launching update batch file '+updateBatch);
      ShellExecute(
        0,
        'open',
        PChar( SysUtils.GetEnvironmentVariable('ComSpec')),
        PChar('/C '+ updatebatch),
        PChar(TempDir),
        SW_HIDE);
      ExitProcess(0);
    end;

  finally
    Files.Free;
  end;
end;


function TISGetUserName : Utf8String;
var
	 pcUser   : PWChar;
	 dwUSize : DWORD;
begin
	 dwUSize := 21; // user name can be up to 20 characters
	 GetMem( pcUser, dwUSize ); // allocate memory for the string
	 try
			if Windows.GetUserNameW( pcUser, dwUSize ) then
				 Result := pcUser;
	 finally
			FreeMem( pcUser ); // now free the memory allocated for the string
	 end;
end;


function GetApplicationName:Utf8String;
begin
  Result := ChangeFileExt(ExtractFileName(ParamStr(0)),'');
end;

function GetPersonalFolder:Utf8String;
begin
  result := GetSpecialFolderLocation(CSIDL_PERSONAL)
end;

function GetAppdataFolder:Utf8String;
begin
  result :=  GetSpecialFolderLocation(CSIDL_APPDATA);
end;

// to store use specific settings for this application
function TISAppuserinipath:Utf8String;
var
  dir : String;
begin
  dir := IncludeTrailingPathDelimiter(GetAppdataFolder)+'tisapps';
  if not DirectoryExists(dir) then
    MkDir(dir);
  Result:=IncludeTrailingPathDelimiter(dir)+GetApplicationName+'.ini';
end;

function SortableVersion(VersionString: String): String;
var
  version,tok : String;
begin
  version := VersionString;
  tok := StrToken(version,'.');
  Result :='';
  repeat
    if StrIsDigit(tok) then
      Result := Result+FormatFloat('0000',StrToInt(tok))
    else
      Result := Result+tok;
    tok := StrToken(version,'.');
  until tok='';
end;

function DateTime2StrUTC(ADatetime: TDateTime): String;
begin
  Result := FormatDateTime('yyyy-mm-dd"T"hhnnss',ADatetime);
end;

function StrUTC2DateTime(AUTCStrDatetime: String): TDateTime;
begin
  Result := StrToDate(copy(AUTCStrDatetime,1,10),'-')+StrToTime(Copy(AUTCStrDatetime,12,8),':');
end;

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

function Dataset2SO(DS: TDataset;AllRecords:Boolean=True): ISuperObject;
var
  rec: ISuperObject;

  procedure Fillrec(rec:ISuperObject);
  var
    i:integer;
  begin
    for i:=0 to DS.Fields.Count-1 do
    begin
      case DS.Fields[i].DataType of
        ftString : rec.S[DS.Fields[i].fieldname] := UTF8Decode(DS.Fields[i].AsString);
        ftInteger : rec.I[DS.Fields[i].fieldname] := DS.Fields[i].AsInteger;
        ftFloat : rec.D[DS.Fields[i].fieldname] := DS.Fields[i].AsFloat;
        ftBoolean : rec.B[DS.Fields[i].fieldname] := DS.Fields[i].AsBoolean;
        ftDateTime : rec.S[DS.Fields[i].fieldname] :=  DateTime2StrUTC(DS.Fields[i].AsDateTime);
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
        case DS.Fields[i].DataType of
          ftString : DS.Fields[i].AsString := UTF8Encode(rec.S[DS.Fields[i].fieldname]);
          ftInteger : DS.Fields[i].AsInteger := rec.I[DS.Fields[i].fieldname];
          ftFloat : DS.Fields[i].AsFloat := rec.D[DS.Fields[i].fieldname];
          ftBoolean : DS.Fields[i].AsBoolean := rec.B[DS.Fields[i].fieldname];

          ftDateTime : if ISO8601DateToDelphiDateTime(rec.S[DS.Fields[i].fieldname],dt) then
            DS.Fields[i].AsDateTime := dt;
        else
          DS.Fields[i].AsString := UTF8Encode(rec.S[DS.Fields[i].fieldname]);
        end;
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

procedure Logger(Msg: String;level:LogLevel=WARNING);
begin
  if level>=currentLogLevel then
  begin
    if IsConsole then
      WriteLn(Msg)
    else
      if Assigned(loghook) then
        loghook(Msg);
  end;
end;

function TISGetComputerName : Utf8String;
var
	 pcComputer : PWChar;
	 dwCSize    : DWORD;
begin
	 dwCSize := MAX_COMPUTERNAME_LENGTH + 1;
	 GetMem( pcComputer, dwCSize ); // allocate memory for the string
	 try
			if Windows.GetComputerNameW( pcComputer, dwCSize ) then
				 Result := pcComputer;
	 finally
			FreeMem( pcComputer ); // now free the memory allocated for the string
	 end;
end;

 type
	PFixedFileInfo = ^TFixedFileInfo;
	TFixedFileInfo = record
		 dwSignature       : DWORD;
		 dwStrucVersion    : DWORD;
		 wFileVersionMS    : WORD;  // Minor Version
		 wFileVersionLS    : WORD;  // Major Version
		 wProductVersionMS : WORD;  // Build Number
		 wProductVersionLS : WORD;  // Release Version
		 dwFileFlagsMask   : DWORD;
		 dwFileFlags       : DWORD;
		 dwFileOS          : DWORD;
		 dwFileType        : DWORD;
		 dwFileSubtype     : DWORD;
		 dwFileDateMS      : DWORD;
		 dwFileDateLS      : DWORD;
	end; // TFixedFileInfo


function ApplicationVersion(Filename:Utf8String=''): Utf8String;
var
	dwHandle, dwVersionSize : DWORD;
	strSubBlock             : String;
	pTemp                   : Pointer;
	pData                   : Pointer;
begin
  Result:='';
	if Filename='' then
    FileName:=ParamStr(0);
	 strSubBlock := '\';

	 // get version information values
	 dwVersionSize := GetFileVersionInfoSizeW( PWideChar( UTF8Decode(FileName) ), // pointer to filename string
																						dwHandle );        // pointer to variable to receive zero

	 // if GetFileVersionInfoSize is successful
	 if dwVersionSize <> 0 then
	 begin
			GetMem( pTemp, dwVersionSize );
			try
				 if GetFileVersionInfo( PChar( FileName ),             // pointer to filename string
																dwHandle,                      // ignored
																dwVersionSize,                 // size of buffer
																pTemp ) then                   // pointer to buffer to receive file-version info.

						if VerQueryValue( pTemp,                           // pBlock     - address of buffer for version resource
															PChar( strSubBlock ),            // lpSubBlock - address of value to retrieve
															pData,                           // lplpBuffer - address of buffer for version pointer
															dwVersionSize ) then             // puLen      - address of version-value length buffer
							 with PFixedFileInfo( pData )^ do
								Result:=IntToSTr(wFileVersionLS)+'.'+IntToSTr(wFileVersionMS)+
											'.'+IntToStr(wProductVersionLS);
			finally
				 FreeMem( pTemp );
			end; // try
	 end; // if dwVersionSize
end;


function ProcessExists(ExeFileName: string): boolean;
{description checks if the process is running. Adapted for freepascal from:
URL: http://www.swissdelphicenter.ch/torry/showcode.php?id=2554}
var
  ContinueLoop: BOOL;
  FSnapshotHandle: THandle;
  FProcessEntry32: TProcessEntry32;
begin
  FSnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  FProcessEntry32.dwSize := SizeOf(FProcessEntry32);
  ContinueLoop := Process32First(FSnapshotHandle, FProcessEntry32);
  Result := False;

  while integer(ContinueLoop) <> 0 do
  begin
    if ((UpperCase(ExtractFileName(FProcessEntry32.szExeFile)) =
      UpperCase(ExeFileName)) or (UpperCase(FProcessEntry32.szExeFile) =
      UpperCase(ExeFileName))) then
    begin
      Result := True;
    end;
    ContinueLoop := Process32Next(FSnapshotHandle, FProcessEntry32);
  end;
  CloseHandle(FSnapshotHandle);
end;

function KillTask(ExeFileName: string): integer;
const
 PROCESS_TERMINATE=$0001;
var
 ContinueLoop: BOOL;
 FSnapshotHandle: THandle;
 FProcessEntry32: TProcessEntry32;
begin
 result := 0;

 FSnapshotHandle := CreateToolhelp32Snapshot
           (TH32CS_SNAPPROCESS, 0);
 FProcessEntry32.dwSize := Sizeof(FProcessEntry32);
 ContinueLoop := Process32First(FSnapshotHandle,
                 FProcessEntry32);

 while integer(ContinueLoop) <> 0 do
 begin
  if ((UpperCase(ExtractFileName(
            FProcessEntry32.szExeFile)) =
     UpperCase(ExeFileName)) or
    (UpperCase(FProcessEntry32.szExeFile) =
     UpperCase(ExeFileName))) then

   Result := Integer(TerminateProcess(OpenProcess(
            PROCESS_TERMINATE, BOOL(0),
            FProcessEntry32.th32ProcessID), 0));

  ContinueLoop := Process32Next(FSnapshotHandle,
                 FProcessEntry32);
 end;

 CloseHandle(FSnapshotHandle);
end;

// from http://theroadtodelphi.wordpress.com/2010/02/21/checking-if-a-tcp-port-is-open-using-delphi-and-winsocks/
function PortTCP_IsOpen(dwPort : Word; ipAddressStr:AnsiString) : boolean;
var
  client : sockaddr_in;
  sock   : Integer;

  ret    : Integer;
  wsdata : WSAData;
begin
 Result:=False;
 ret := WSAStartup($0002, wsdata); //initiates use of the Winsock DLL
  if ret<>0 then exit;
  try
    client.sin_family      := AF_INET;  //Set the protocol to use , in this case (IPv4)
    client.sin_port        := htons(dwPort); //convert to TCP/IP network byte order (big-endian)
    client.sin_addr.s_addr := inet_addr(PAnsiChar(ipAddressStr));  //convert to IN_ADDR  structure
    sock  :=socket(AF_INET, SOCK_STREAM, 0);    //creates a socket
    Result:=connect(sock,client,SizeOf(client))=0;  //establishes a connection to a specified socket
  finally
    WSACleanup;
  end;
end;

function GetIPFromHost(const HostName: string): string;
type
  TaPInAddr = array[0..10] of PInAddr;
  PaPInAddr = ^TaPInAddr;
var
  phe: PHostEnt;
  pptr: PaPInAddr;
  i: Integer;
  GInitData: TWSAData;
begin
  WSAStartup($101, GInitData);
  Result := '';
  phe := GetHostByName(PChar(HostName));
  if phe = nil then Exit;
  pPtr := PaPInAddr(phe^.h_addr_list);
  i := 0;
  while pPtr^[i] <> nil do
  begin
    Result := inet_ntoa(pptr^[i]^);
    Inc(i);
  end;
  WSACleanup;
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

function RunTask(cmd: utf8string;var ExitStatus:integer;WorkingDir:utf8String=''): utf8string;
var
  AProcess: TProcess;
  AStringList: TStringList;
begin
    AProcess := TProcess.Create(nil);
    AStringList := TStringList.Create;
    try
      AProcess.CommandLine := cmd;
      if WorkingDir<>'' then
        AProcess.CurrentDirectory := ExtractFilePath(cmd);
      AProcess.Options := AProcess.Options + [poStderrToOutPut, poWaitOnExit, poUsePipes];
      AProcess.Execute;
      while AProcess.Running do;
      AStringList.LoadFromStream(AProcess.Output);
      Result := AStringList.Text;
      ExitStatus:= AProcess.ExitStatus;
    finally
      AStringList.Free;
      AProcess.Free;
    end;
end;


function CheckOpenPort(dwPort : Word; ipAddressStr:AnsiString;timeout:integer=5):boolean;
var
  St:TDateTime;
  ip:String;
begin
  ip := GetIPFromHost(ipAddressStr);
  St := Now;
  While not PortTCP_IsOpen(dwPort,ip) and (Now-St<timeout/24/3600) do
    Sleep(1000);
  Result:=PortTCP_IsOpen(dwPort,ip);
end;

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
        ');'+
        'create index idx_package_name on wapt_repo(Package);');

    if lst.IndexOf('wapt_localstatus')<0 then
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
        ');'+
        'create index idx_localstatus_name on wapt_localstatus(Package);');

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
  query : TSQLQuery;
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

end.

