unit waptwinutils;
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
{$mode delphiunicode}

interface

uses
  Classes,windows,SysUtils,superobject, ShellApi, JwaWinbase;

function DNSAQuery(name:AnsiString):ISuperObject;
function DNSSRVQuery(name:AnsiString):ISuperObject;
function DNSCNAMEQuery(name:AnsiString):ISuperObject;

Function GetDNSServers:ISuperObject;
function GetDNSServer:AnsiString;
function GetDNSDomain:AnsiString;

Function IPV4ToInt(ipaddr:AnsiString):LongWord;
Function SameIPV4Subnet(ip1,ip2,netmask:AnsiString):Boolean;

function GetDosOutput(const CommandLine: ansistring; WorkDir: ansistring; var Text: ansistring): boolean;
function RunAsAdmin(const Handle: Hwnd; aFile : Ansistring; Params: Ansistring): Boolean;

/// <summary>
///   Runs a console application and captures the stdoutput and
///   stderror.</summary>
/// <param name="CmdLine">The commandline contains the full path to
///   the executable and the necessary parameters. Don't forget to
///   quote filenames with "" if the path contains spaces.</param>
/// <param name="Output">Receives the console stdoutput.</param>
/// <param name="Error">Receives the console stderror.</param>
/// <param name="Input">Send to stdinput of the process.</param>
/// <param name="Wait">[milliseconds] Maximum of time to wait,
///   until application has finished. After reaching this timeout,
///   the application will be terminated and False is returned as
///   result.</param>
/// <returns>True if process could be started and did not reach the
///   timeout.</returns>
// Adapted From http://www.martinstoeckli.ch/delphi/  (
function Run(CmdLine: WideString;
  const Input: RawByteString = '';
  const Wait: DWORD = 3600000;user:WideString='';domain:WideString='';password:WideString='';onpoll:TNotifyEvent=Nil): RawByteString;

const
  LOGON_WITH_PROFILE = $00000001;

function CreateProcessWithLogonW(lpUsername, lpDomain, lpPassword: PWideChar;
  dwLogonFlags: dword; lpApplicationName, lpCommandLine: PWideChar;
  dwCreationFlags: dword; lpEnvironment: pointer;
  lpCurrentDirectory: PWideChar; lpStartupInfo: PStartUpInfoW;
  lpProcessInfo: PProcessInformation): boolean; stdcall;
  external 'advapi32.dll';

function NetworkConfig: ISuperObject;
function ComputerSystem: ISuperObject;
function BasicRegistrationData: ISuperObject;

function ReadRegEntry(strSubKey, strValueName: ansistring): ansistring;

function WaptGetIniPath: string;
function WaptIniReadString(Parameter, DefaultValue: string): string;
function LocalWaptVersion: ansistring;

implementation

uses Variants, registry, sysconst, JwaIpHlpApi,
  JwaIpTypes, JwaWinDNS, JwaWinsock2, tisinifiles, soutils;


Function IPV4ToInt(ipaddr:AnsiString):LongWord;
begin
  Result := inet_addr(PAnsiChar(ipaddr));
end;

function IPV4ToString(ipv4:LongWord):AnsiString;
begin
  Result :=  format('%D.%D.%D.%D',[ipv4  and $FF, (ipv4  shr 8) and $FF,  (ipv4  shr 16) and $FF, (ipv4  shr 24) and $FF]);
end;

function DNSAQuery(name: AnsiString): ISuperObject;
var
  ppQueryResultsSet : PDNS_RECORD;
  retvalue: Integer;
  res : AnsiString;
  ip,ips: ISuperObject;
begin
  Result := TSuperObject.Create(stArray);
  ppQueryResultsSet := Nil;
  retvalue := DnsQuery(
    PAnsiChar(name),
    DNS_TYPE_A,
    DNS_QUERY_BYPASS_CACHE or DNS_QUERY_NO_LOCAL_NAME or DNS_QUERY_NO_HOSTS_FILE,
    Nil,
    @ppQueryResultsSet,
    Nil);
  if (retvalue=0) and (ppQueryResultsSet<>Nil) then
  try
    while ppQueryResultsSet<>Nil do
    begin
      if (ppQueryResultsSet^.wType=DNS_TYPE_CNAME) then
      begin
        // recursive query if a CNAME is returned.
        // very strange ... ppQueryResultsSet^.Data.PTR works but ppQueryResultsSet^.Data.CNAME not... same structure pNameHost in both cases.
        ips := DNSAQuery(ppQueryResultsSet^.Data.PTR.pNameHost);
        for ip in ips do
          Result.AsArray.Add(ip.AsString);
      end
      else
      if (ppQueryResultsSet^.wType=DNS_TYPE_A) and (ppQueryResultsSet^.Data.A.IpAddress<>0) and (LowerCase(ppQueryResultsSet^.pName) = LowerCase(name)) then
      begin
        res := IPV4ToString(ppQueryResultsSet^.Data.A.IpAddress);
        UniqueString(res);
        Result.AsArray.Add(res);
      end;
      ppQueryResultsSet:= ppQueryResultsSet^.pNext;
    end;
  finally
    DnsRecordListFree(ppQueryResultsSet,DnsFreeRecordList);
  end;
end;

//query current dns server for SRV record and return a list of {name,priority,weight,port}
function DNSSRVQuery(name:AnsiString):ISuperObject;
var
  ppQueryResultsSet : PDNS_RECORD;
  retvalue: Integer;
  res : AnsiString;
  rec:ISuperObject;
begin
  Result := TSuperObject.Create(stArray);
  ppQueryResultsSet := Nil;
  retvalue := DnsQuery(
    PAnsiChar(name),
    DNS_TYPE_SRV,
    DNS_QUERY_BYPASS_CACHE or DNS_QUERY_NO_LOCAL_NAME or DNS_QUERY_NO_HOSTS_FILE,
    Nil,
    @ppQueryResultsSet,
    Nil);
  if (retvalue=0) and (ppQueryResultsSet<>Nil) then
  try
    while ppQueryResultsSet<>Nil do
    begin
      rec:= TSuperObject.Create(stObject);
      if ppQueryResultsSet^.wType=DNS_TYPE_SRV then
      begin
        res := ppQueryResultsSet^.Data.SRV.pNameTarget;
        UniqueString(res);
        rec.S['name'] := res;
        rec.I['port'] := ppQueryResultsSet^.Data.SRV.wPort;
        rec.I['priority'] := ppQueryResultsSet^.Data.SRV.wPriority;
        rec.I['weight'] := ppQueryResultsSet^.Data.SRV.wWeight;
        Result.AsArray.Add(rec);
      end;
      ppQueryResultsSet:= ppQueryResultsSet^.pNext;
    end;
    SortByFields(Result,['priority','port']);
  finally
    DnsRecordListFree(ppQueryResultsSet,DnsFreeRecordList);
  end;
end;

//query current dns server for CNAME record and return a list of {name}
function DNSCNAMEQuery(name:AnsiString):ISuperObject;
var
  ppQueryResultsSet : PDNS_RECORD;
  retvalue: Integer;
  res : AnsiString;
begin
  Result := TSuperObject.Create(stArray);
  ppQueryResultsSet := Nil;
  retvalue := DnsQuery(
    PAnsiChar(name),
    DNS_TYPE_CNAME,
    DNS_QUERY_BYPASS_CACHE or DNS_QUERY_NO_LOCAL_NAME or DNS_QUERY_NO_HOSTS_FILE,
    Nil,
    @ppQueryResultsSet,
    Nil);
  if (retvalue=0) and (ppQueryResultsSet<>Nil) then
  try
    while ppQueryResultsSet<>Nil do
    begin
      // strange ppQueryResultsSet^.Data.PTR works but not ppQueryResultsSet^.Data.CNAME
      if (ppQueryResultsSet^.wType=DNS_TYPE_CNAME) and (ppQueryResultsSet^.Data.PTR.pNameHost<>Nil) then
      begin
        res := ppQueryResultsSet^.Data.PTR.pNameHost;
        UniqueString(res);
        Result.AsArray.Add(res);
      end;
      ppQueryResultsSet:= ppQueryResultsSet^.pNext;
    end;
  finally
    DnsRecordListFree(ppQueryResultsSet,DnsFreeRecordList);
  end;
end;

type
  PFixedFileInfo = ^TFixedFileInfo;

  TFixedFileInfo = record
    dwSignature: DWORD;
    dwStrucVersion: DWORD;
    wFileVersionMS: word;  // Minor Version
    wFileVersionLS: word;  // Major Version
    wProductVersionMS: word;  // Build Number
    wProductVersionLS: word;  // Release Version
    dwFileFlagsMask: DWORD;
    dwFileFlags: DWORD;
    dwFileOS: DWORD;
    dwFileType: DWORD;
    dwFileSubtype: DWORD;
    dwFileDateMS: DWORD;
    dwFileDateLS: DWORD;
  end; // TFixedFileInfo


function GetApplicationVersion(Filename: ansistring = ''): ansistring;
var
  dwHandle, dwVersionSize: DWORD;
  strSubBlock: ansistring;
  pTemp: Pointer;
  pData: Pointer;
begin
  Result := '';
  if Filename = '' then
    FileName := ParamStr(0);
  strSubBlock := '\';

  // get version information values
  dwVersionSize := GetFileVersionInfoSizeW(PWideChar(UTF8Decode(FileName)),
    // pointer to filename string
    dwHandle);        // pointer to variable to receive zero

  // if GetFileVersionInfoSize is successful
  if dwVersionSize <> 0 then
  begin
    GetMem(pTemp, dwVersionSize);
    try
      if GetFileVersionInfo(PAnsiChar(FileName),
        // pointer to filename string
        dwHandle,                      // ignored
        dwVersionSize,                 // size of buffer
        pTemp) then
        // pointer to buffer to receive file-version info.

        if VerQueryValue(pTemp,
          // pBlock     - address of buffer for version resource
          PAnsiChar(strSubBlock),
          // lpSubBlock - address of value to retrieve
          pData,
          // lplpBuffer - address of buffer for version pointer
          dwVersionSize) then
          // puLen      - address of version-value length buffer
          with PFixedFileInfo(pData)^ do
            Result := IntToStr(wFileVersionLS) + '.' + IntToStr(wFileVersionMS) +
              '.' + IntToStr(wProductVersionLS) + '.' + IntToStr(wProductVersionMS);
    finally
      FreeMem(pTemp);
    end; // try
  end; // if dwVersionSize
end;


// launch aFile with Params asking for a different user
function RunAsAdmin(const Handle: Hwnd; aFile : Ansistring; Params: Ansistring): Boolean;
var
  sei:  TSHELLEXECUTEINFO;
begin
  FillChar(sei, SizeOf(sei), 0);
  With sei do begin
     cbSize := SizeOf(sei);
     Wnd := Handle;
     //fMask := SEE_MASK_FLAG_DDEWAIT or SEE_MASK_FLAG_NO_UI;
     fMask := SEE_MASK_FLAG_DDEWAIT;
     lpVerb := 'runAs';
     lpFile := PAnsiChar(aFile);
     lpParameters := PAnsiChar(Params);
     nShow := SW_SHOWNORMAL;
  end;
  Result := ShellExecuteExA(@sei);
end;

//Given a string and a separator, return next token and remove this token from start of source string.
function StrToken(var S: ansistring; Separator: ansistring): ansistring;
var
  I: SizeInt;
begin
  I := Pos(Separator, S);
  if I <> 0 then
  begin
    Result := Copy(S, 1, I - 1);
    Delete(S, 1, I + length(Separator) - 1);
  end
  else
  begin
    Result := S;
    S := '';
  end;
end;

//Decodes a string of lines like key=value as returned by wmic /VALUE command.
function DecodeKeyValue(wmivalue: ansistring; LowerKey: boolean = True;
  ConvertArrayValue: boolean = True): ISuperObject;
var
  line, key, Value: ansistring;
  CurrObject: ISuperObject;
  isArray: boolean;
begin
  Result := TSuperObject.Create(stArray);
  CurrObject := nil;
  repeat
    line := trim(StrToken(wmivalue, #13#10));
    if line <> '' then
    begin
      if CurrObject = nil then
      begin
        CurrObject := SO;
        Result.AsArray.Add(CurrObject);
      end;
      key := StrToken(line, '=');
      Value := trim(line);
      if LowerKey then
        key := LowerCase(Key);
      if ConvertArrayValue then
      begin
        isArray := False;
        if (Value <> '') and (Value[1] = '{') then
        begin
          Value[1] := '[';
          isArray := True;
        end;
        if isArray and (Value <> '') and (Value[length(Value)] = '}') then
          Value[length(Value)] := ']';
        if isArray then
          CurrObject[key] := SO(Value)
        else
          CurrObject.S[key] := Value;
      end
      else
        CurrObject.S[key] := Value;
    end
    else
      CurrObject := nil;
  until trim(wmivalue) = '';
end;


// Retrieve enabled network interfaces with ip parameters.
function NetworkConfig: ISuperObject;
var
  res: ansistring;
begin
  if GetDosOutput(
    'wmic NICCONFIG where ipenabled=True get MACAddress, DefaultIPGateway, IPAddress, IPSubnet, DNSHostName, DNSDomain /VALUE',
    '', res) then
    Result := DecodeKeyValue(res)
  else
    Result := SO(stArray);
end;


// Run Commandline, return output in Text var, and return True is command has been launched properly.
function GetDosOutput(const CommandLine: ansistring; WorkDir: ansistring; var Text: ansistring): boolean;
var
  SA: TSecurityAttributes;
  SI: TStartupInfo;
  PI: TProcessInformation;
  StdOutPipeRead, StdOutPipeWrite: THandle;
  WasOK: boolean;
  Buffer: array[0..255] of AnsiChar;
  BytesRead: cardinal;
  Line: ansistring;
begin
  with SA do
  begin
    nLength := SizeOf(SA);
    bInheritHandle := True;
    lpSecurityDescriptor := nil;
  end;
  // create pipe for standard output redirection
  CreatePipe(StdOutPipeRead, // read handle
    StdOutPipeWrite, // write handle
    @SA, // security attributes
    0 // number of bytes reserved for pipe - 0 default
    );
  try
    // Make child process use StdOutPipeWrite as standard out,
    // and make sure it does not show on screen.
    with SI do
    begin
      FillChar(SI, SizeOf(SI), 0);
      cb := SizeOf(SI);
      dwFlags := STARTF_USESHOWWINDOW or STARTF_USESTDHANDLES;
      wShowWindow := SW_HIDE;
      hStdInput := GetStdHandle(STD_INPUT_HANDLE); // don't redirect stdinput
      hStdOutput := StdOutPipeWrite;
      hStdError := StdOutPipeWrite;
    end;

    // launch the command line compiler
    //WorkDir := 'C:\';
    if workdir = '' then
      workdir := GetCurrentDir;
    Result := CreateProcess(nil, PAnsiChar(CommandLine), nil,
      nil, True, 0, nil, PAnsiChar(WorkDir), SI, PI);

    // Now that the handle has been inherited, close write to be safe.
    // We don't want to read or write to it accidentally.
    CloseHandle(StdOutPipeWrite);
    // if process could be created then handle its output
    if Result then
      try
        // get all output until dos app finishes
        Line := '';
        repeat
          // read block of characters (might contain carriage returns and  line feeds)
          WasOK := windows.ReadFile(StdOutPipeRead, Buffer, 255, BytesRead, nil);

          // has anything been read?
          if BytesRead > 0 then
          begin
            // finish buffer to PAnsiChar
            Buffer[BytesRead] := #0;
            // combine the buffer with the rest of the last run
            Line := Line + Buffer;
          end;
        until not WasOK or (BytesRead = 0);
        // wait for console app to finish (should be already at this point)
        WaitForSingleObject(PI.hProcess, INFINITE);
      finally
        // Close all remaining handles
        CloseHandle(PI.hThread);
        CloseHandle(PI.hProcess);
      end;
  finally
    Text := Line;
    CloseHandle(StdOutPipeRead);
  end;
end;


Function GetDNSServers:ISuperObject;
var
  pFI: PFixedInfo;
  pIPAddr: PIPAddrString;
  OutLen: Cardinal;
  ip:AnsiString;
begin
  Result := TSuperObject.Create(stArray);
  OutLen := SizeOf(TFixedInfo);
  GetMem(pFI, SizeOf(TFixedInfo));
  try
    if GetNetworkParams(pFI, OutLen) = ERROR_BUFFER_OVERFLOW then
    begin
      ReallocMem(pFI, OutLen);
      if GetNetworkParams(pFI, OutLen) <> NO_ERROR then Exit;
    end;
    // If there is no network available there may be no DNS servers defined
    if pFI^.DnsServerList.IpAddress.S[0] = #0 then Exit;
    // Add first server
    ip := pFI^.DnsServerList.IpAddress.S;
    Result.AsArray.Add(ip);
    // Add rest of servers
    pIPAddr := pFI^.DnsServerList.Next;
    while Assigned(pIPAddr) do
    begin
      ip := pIPAddr^.IpAddress.S;
      Result.AsArray.Add(ip);
      pIPAddr := pIPAddr^.Next;
    end;
  finally
    FreeMem(pFI);
  end;
end;

function GetDNSServer:AnsiString;
var
  dnsserv : ISuperObject;
begin
  dnsserv := GetDNSServers;
  if dnsserv.AsArray.Length>0 then
    result := dnsserv.AsArray.S[0]
  else
    result :='';
end;

//Get dns domain from global tcpip parameters in registry
function GetDNSDomain:AnsiString;
var
  reg:TRegistry;
begin
  reg := TRegistry.create;
  try
    reg.RootKey:=HKEY_LOCAL_MACHINE;
    if reg.OpenKeyReadOnly('SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters') then
    begin
      if reg.ValueExists('Domain') then
        Result := reg.ReadString('Domain');
      if Result='' then
        if reg.ValueExists('DhcpDomain') then
          Result := reg.ReadString('DhcpDomain');
    end;
  finally
    reg.Free;
  end;
end;

Function SameIPV4Subnet(ip1,ip2,netmask:AnsiString):Boolean;
begin
    Result := (IPV4ToInt(ip1) and IPV4ToInt(netmask)) = (IPV4ToInt(ip2) and IPV4ToInt(netmask));
end;

function LocalWaptVersion: ansistring;
var
  local_version: ansistring;
  i:integer;
begin
  Result := '';
  try
    local_version := ReadRegEntry(
      'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WAPT_is1',
      'DisplayVersion');
  except
    try
      local_version := ReadRegEntry(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WAPT_is1',
        'DisplayVersion');
    except
      local_version := '';
    end;
    // check if looks like actual version string.
  end;
  for i := 1 to length(local_version) do
    if CharInSet(local_version[i],['0'..'9','-','.']) then
      Result := Result + local_version[i];
end;

// Compare version member by member as int or string
function CompareVersion(v1, v2: ansistring): integer;
var
  tok1, tok2: ansistring;
begin
  repeat
    tok1 := StrToken(v1, '.');
    tok2 := StrToken(v2, '.');
    if (tok1 <> '') and (tok2 <> '') then
      try
        Result := StrToInt(tok1) - StrToInt(tok2);
      except
        Result := CompareStr(tok1, tok2);
      end;
    if (Result <> 0) or (tok1 = '') or (tok2 = '') then
      break;
  until (Result <> 0) or (tok1 = '') or (tok2 = '');
end;

function GetComputerName: ansistring;
var
  buffer: array[0..255] of ansichar;
  size: dword;
begin
  size := 256;
  if Windows.GetComputerName(@buffer, size) then
    Result := buffer
  else
    Result := '';
end;

// Send to the WAPT Server the minimum registration information
function BasicRegistrationData: ISuperObject;
var
  uuid, json: string;
  Data, nw, intf, computer: ISuperObject;

  procedure addkey(key, Value: string);
  begin
    json := json + Format('"%s":"%s",', [key, Value]);
  end;

begin
  Data := SO;
  computer := ComputerSystem;
  uuid := WaptIniReadString('uuid', computer.S['uuid']);

  Data.S['uuid'] := uuid;
  Data.S['wapt.wapt-exe-version'] := LocalWaptVersion;
  Data.S['host.computer_name'] := GetComputerName;
  Data.S['host.system_productname'] := computer.S['name'];
  Data.S['host.system_manufacturer'] := computer.S['vendor'];
  Data.S['host.system_serialnr'] := computer.S['identifyingnumber'];
  Data.S['dmi.Chassis_Information.Serial_Number'] := computer.S['identifyingnumber'];
  nw := NetworkConfig;
  for intf in nw do
  begin
    if intf.AsObject.Exists('defaultipgateway') then
    begin
   {
    "ipaddress": [
     "192.168.149.201"],
    "defaultipgateway": [
     "192.168.149.254"],
    "dnshostname": "wstestwapt",
    "ipsubnet": [
     "255.255.255.0"],
    "macaddress": "08:00:27:72:E9:E4",
    "dnsdomain": "tranquilit.local"
   }
      Data.S['host.dns_domain'] := LowerCase(nw.AsArray[0].S['dnsdomain']);
      Data.S['host.connected_ips'] := nw.AsArray[0].A['ipaddress'].S[0];
      Data.S['host.mac'] := lowercase(nw.AsArray[0].S['macaddress']);
      Data.S['host.computer_fqdn'] :=
        lowercase(nw.AsArray[0].S['dnshostname'] + '.' + nw.AsArray[0].S['dnsdomain']);
      break;
    end;
  end;
  result := Data;
end;


//Get basic identification information fir the computer using wmic
function ComputerSystem: ISuperObject;
var
  Res: ansistring;
begin
  if GetDosOutput(
    'wmic PATH Win32_ComputerSystemProduct GET UUID,IdentifyingNumber,Name,Vendor /VALUE',
      '', res) then
  begin
    Result := DecodeKeyValue(res);
    if Result.DataType = stArray then
       Result := Result.AsArray[0];
      {UUID=4C4C4544-004E-3510-8051-C7C04F325131}
  end
  else
    Result := SO();
end;


function ReadRegEntry(strSubKey, strValueName: ansistring): ansistring;
var
  Key: HKey;
  subkey: PAnsiChar;
  Buffer: array[0..255] of ansichar;
  Size: cardinal;
begin
  Key := 0;
  Result := 'ERROR';
  Size := SizeOf(Buffer);
  subkey := PAnsiChar(strSubKey);
  if RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, Key) = ERROR_SUCCESS then
    try
      if RegQueryValueEx(Key, PAnsiChar(strValueName), nil, nil, @Buffer, @Size) =
        ERROR_SUCCESS then
        Result := Buffer;
    finally
      RegCloseKey(Key);
    end
  else
    raise Exception.Create('Wrong key HKLM\' + strSubKey);
end;


function WaptGetIniPath: string;
begin
  if FileExists('c:\wapt\wapt-get.ini') then
    Result := 'c:\wapt\wapt-get.ini'
  else
  if FileExists(SysUtils.GetEnvironmentVariable('ProgramFiles(x86)') +
    '\wapt\wapt-get.ini') then
    Result := SysUtils.GetEnvironmentVariable('ProgramFiles(x86)') + '\wapt\wapt-get.ini'
  else
  if FileExists(SysUtils.GetEnvironmentVariable('ProgramFiles') + '\wapt\wapt-get.ini') then
    Result := SysUtils.GetEnvironmentVariable('ProgramFiles') + '\wapt\wapt-get.ini'
  else
    Result := 'c:\wapt\wapt-get.ini';
end;

function WaptIniReadString(Parameter, DefaultValue: string): string;
begin
  if FileExists(WaptGetIniPath) then
    Result := IniReadString(WaptGetIniPath, 'global', Parameter, DefaultValue)
  else
    Result := DefaultValue;
end;


// Run

type
  TRunReadPipeThread = class(TThread)
  protected
    FPipe: THandle;
    FContent: TStringStream;
    function Get_Content: RawByteString;
    procedure Execute; override;
  public
    constructor Create(const Pipe: THandle);
    destructor Destroy; override;
    property Content: RawByteString read Get_Content;
  end;

  TRunWritePipeThread = class(TThread)
  protected
    FPipe: THandle;
    FContent: TStringStream;
    procedure Execute; override;
  public
    constructor Create(const Pipe: THandle; const Content: RawByteString);
    destructor Destroy; override;
  end;

{ TStoReadPipeThread }

constructor TRunReadPipeThread.Create(const Pipe: THandle);
begin
  FPipe := Pipe;
  FContent := TStringStream.Create('');
  inherited Create(False); // start running
end;

destructor TRunReadPipeThread.Destroy;
begin
  FContent.Free;
  inherited Destroy;
end;

procedure TRunReadPipeThread.Execute;
const
  BLOCK_SIZE = 4096;
var
  iBytesRead: DWORD;
  myBuffer: array[0..BLOCK_SIZE-1] of Byte;
begin
  iBytesRead := 0;
  repeat
    // try to read from pipe
    if Windows.ReadFile(FPipe, myBuffer, BLOCK_SIZE, iBytesRead, nil) then
      FContent.Write(myBuffer, iBytesRead);
  // a process may write less than BLOCK_SIZE, even if not at the end
  // of the output, so checking for < BLOCK_SIZE would block the pipe.
  until (iBytesRead = 0);
end;

function TRunReadPipeThread.Get_Content: RawByteString;
begin
  Result := FContent.DataString;
end;

{ TStoWritePipeThread }

constructor TRunWritePipeThread.Create(const Pipe: THandle;
  const Content: RawByteString);
begin
  FPipe := Pipe;
  FContent := TStringStream.Create(Content);
  inherited Create(False); // start running
end;

destructor TRunWritePipeThread.Destroy;
begin
  FContent.Free;
  if (FPipe <> 0) then
    CloseHandle(FPipe);
  inherited Destroy;
end;

procedure TRunWritePipeThread.Execute;
const
  BLOCK_SIZE = 4096;
var
  myBuffer: array[0..BLOCK_SIZE-1] of Byte;
  iBytesToWrite: DWORD;
  iBytesWritten: DWORD;
begin
  iBytesToWrite := FContent.Read(myBuffer, BLOCK_SIZE);
  while (iBytesToWrite > 0) do
  begin
    Windows.WriteFile(FPipe, myBuffer, iBytesToWrite, iBytesWritten, nil);
    iBytesToWrite := FContent.Read(myBuffer, BLOCK_SIZE);
  end;
  // close our handle to let the other process know, that
  // there won't be any more data.
  CloseHandle(FPipe);
  FPipe := 0;
end;

function Run(CmdLine: WideString;
  const Input: RawByteString = '';
  const Wait: DWORD = 3600000;user:WideString='';domain:WideString='';password:WideString='';onpoll:TNotifyEvent=Nil): RawByteString;
var
  mySecurityAttributes: SECURITY_ATTRIBUTES;
  myStartupInfo: STARTUPINFOW;
  myProcessInfo: PROCESS_INFORMATION;
  hPipeInputRead, hPipeInputWrite: THandle;
  hPipeOutputRead, hPipeOutputWrite: THandle;
  hPipeErrorRead, hPipeErrorWrite: THandle;
  myWriteInputThread: TRunWritePipeThread;
  myReadOutputThread: TRunReadPipeThread;
  myReadErrorThread: TRunReadPipeThread;
  iWaitRes: Integer;

  wparams:WideString;
  output,error:RawByteString;

  exitCode:LongWord;

  start_ms:DWORD;

const
  pollwait:DWORD = 500;

begin
  try
    ZeroMemory(@mySecurityAttributes, SizeOf(SECURITY_ATTRIBUTES));
    mySecurityAttributes.nLength := SizeOf(SECURITY_ATTRIBUTES);
    mySecurityAttributes.bInheritHandle := TRUE;
    // create pipe to set stdinput
    hPipeInputRead := 0;
    hPipeInputWrite := 0;
    CreatePipe(hPipeInputRead, hPipeInputWrite, @mySecurityAttributes, 0);
    CreatePipe(hPipeOutputRead, hPipeOutputWrite, @mySecurityAttributes, 0);
    CreatePipe(hPipeErrorRead, hPipeErrorWrite, @mySecurityAttributes, 0);

    try
      // prepare startupinfo structure
      ZeroMemory(@myStartupInfo, SizeOf(STARTUPINFO));
      myStartupInfo.cb := Sizeof(STARTUPINFO);

      // hide application
      myStartupInfo.dwFlags := STARTF_USESHOWWINDOW;
      myStartupInfo.wShowWindow := SW_HIDE;
      // assign pipes
      myStartupInfo.dwFlags := myStartupInfo.dwFlags or STARTF_USESTDHANDLES;
      myStartupInfo.hStdInput := hPipeInputRead;
      myStartupInfo.hStdOutput := hPipeOutputWrite;
      myStartupInfo.hStdError := hPipeErrorWrite;

      // since Delphi calls CreateProcessW, literal strings cannot be used anymore
      UniqueString(CmdLine);

      // start the process
      wparams := CmdLine;
      if user<>'' then
      begin
        UniqueString(user);
        UniqueString(password);
        UniqueString(domain);
        if not CreateProcessWithLogonW(PWidechar(user),pwidechar(domain),pwidechar(password),0, Nil,PWideChar(wparams), CREATE_NEW_CONSOLE,nil,nil,@myStartupInfo, @myProcessInfo) then
          RaiseLastOSError;
      end
      else
      begin
        if not CreateProcessW(Nil,PWideChar(wparams),  Nil,Nil, True, CREATE_NEW_CONSOLE,nil,nil,myStartupInfo,myProcessInfo) then
          RaiseLastOSError();
      end;

    finally
      // close the ends of the pipes, now used by the process
      CloseHandle(hPipeInputRead);
      CloseHandle(hPipeOutputWrite);
      CloseHandle(hPipeErrorWrite);
    end;

    myWriteInputThread := Nil;
    myReadOutputThread := Nil;
    myReadErrorThread := Nil;

    myWriteInputThread := TRunWritePipeThread.Create(hPipeInputWrite, Input);
    myReadOutputThread := TRunReadPipeThread.Create(hPipeOutputRead);
    myReadErrorThread := TRunReadPipeThread.Create(hPipeErrorRead);
    try
      start_ms := GetTickCount;
      try
        repeat
          // wait unitl there is no more data to receive, or the timeout is reached
          iWaitRes := WaitForSingleObject(myProcessInfo.hProcess, pollwait);
          if Assigned(onpoll) then
            onpoll(Nil);
          // timeout reached ?
        until ((GetTickCount-start_ms > Wait) and  (iWaitRes = WAIT_TIMEOUT)) or (iWaitRes <> WAIT_TIMEOUT);
      except
        TerminateProcess(myProcessInfo.hProcess, UINT(ERROR_CANCELLED));
        raise;
      end;
      if (GetTickCount-start_ms > Wait) then
      begin
        TerminateProcess(myProcessInfo.hProcess, UINT(ERROR_CANCELLED));
        raise Exception.Create('Timeout running '+CmdLine);
      end;
      // return output
      myReadOutputThread.WaitFor;
      Output := myReadOutputThread.Content;
      Result := output;
      myReadErrorThread.WaitFor;
      Error := myReadErrorThread.Content;
      exitCode :=0;
      if not GetExitCodeProcess(myProcessInfo.hProcess, exitCode) or (exitCode>0) then
        raise EOSError.CreateFmt(SOSError, [exitCode, SysErrorMessage(exitCode)+' : '+Error])
    finally
      if myWriteInputThread<>Nil then  myWriteInputThread.Free;
      if myReadOutputThread<>Nil then myReadOutputThread.Free;
      if myReadErrorThread<>Nil then myReadErrorThread.Free;
      CloseHandle(myProcessInfo.hThread);
      CloseHandle(myProcessInfo.hProcess);
    end;

  finally
    // close our ends of the pipes
    CloseHandle(hPipeOutputRead);
    CloseHandle(hPipeErrorRead);

  end;
end;



end.

