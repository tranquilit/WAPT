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

interface

uses
  Classes,SysUtils,superobject, process;


Function IPV4ToInt(ipaddr:AnsiString):LongWord;
Function SameIPV4Subnet(ip1,ip2,netmask:AnsiString):Boolean;

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


function WaptGuessBaseDir: Utf8String;
function AGetComputerName: ansistring;
function AGetUserName: ansistring;


implementation

uses Variants, registry, sysconst, tisinifiles, soutils, dynlibs;

Function IPV4ToInt(ipaddr:AnsiString):LongWord;
var
  S: TStrings;
begin
  S := TStringList.Create;
  try
    S.Delimiter := '.';
    S.DelimitedText := ipaddr;
    Result := (StrToInt(S[0]) shl 24) + (StrToInt(S[1]) shl 16);
    Result += (StrToInt(S[2]) shl 8) + StrToInt(S[3]);
  finally
    S.Free;
  end;
end;

function IPV4ToString(ipv4:LongWord):AnsiString;
begin
  Result :=  format('%D.%D.%D.%D',[ipv4  and $FF, (ipv4  shr 8) and $FF,  (ipv4  shr 16) and $FF, (ipv4  shr 24) and $FF]);
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

function AGetComputerName: ansistring;
var
  AProcess: TProcess;
  AStringList: TStringList;
begin
  AProcess := TProcess.Create(nil);
  AStringList := TStringList.Create();
  AProcess.Executable := 'hostname';
  AProcess.Options := AProcess.Options + [poWaitOnExit, poUsePipes];
  AProcess.Execute;
  AStringList.LoadFromStream(AProcess.Output);
  Result:=AStringList.Strings[0];
  AStringList.Free;
  AProcess.Free;
  WriteLn(Result);
end;

function AGetUserName: ansistring;
var
  buffer: array[0..255] of ansichar;
begin
  Result := GetEnvironmentVariable('USER');
end;

function WaptGuessBaseDir: Utf8String;
begin

  if FileExists('c:\wapt') then
    Result := 'c:\wapt'
  else
  if FileExists(SysUtils.GetEnvironmentVariable('ProgramFiles(x86)') +
    '\wapt') then
    Result := SysUtils.GetEnvironmentVariable('ProgramFiles(x86)') + '\wapt'
  else
  if FileExists(SysUtils.GetEnvironmentVariable('ProgramFiles') + '\wapt') then
    Result := SysUtils.GetEnvironmentVariable('ProgramFiles') + '\wapt'
  else
    Result := 'c:\wapt';
end;

function GetApplicationVersion(Filename: ansistring = ''): ansistring;
begin
  Result := ''; // TODO change
end;

end.

