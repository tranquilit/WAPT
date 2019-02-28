library waptsetuputil;

{$mode objfpc}{$H+}

{$ifndef WINDOWS}
{$error}
{$endif}

{$R *.res}

uses
  sysutils,
  Classes,
  superobject,
  windows,
  waptwinutils,
  tisinifiles,
  IdUri;


// global buffer for return
var
  ip: String;
  dnsname: String;

function GetComputerConnectedIP:PChar; stdcall;
var
  nw: ISuperObject;
begin
  nw := NetworkConfig;
  if Assigned(nw.AsArray) then
    ip := lowercase(nw.AsArray[0]['ipaddress'].AsArray.S[0])
  else
    ip := '';
  Result := @ip;
end;

function GetComputerDNSName:PChar; stdcall;
var
  nw: ISuperObject;
begin
  nw := NetworkConfig;
  dnsname := lowercase(nw.AsArray[0].S['dnshostname'] + '.' + nw.AsArray[0].S['dnsdomain']);
  Result := @dnsname;
end;

function GetComputerDNSNameOrIP:PChar; stdcall;
var
  nw,DnsResult: ISuperObject;
  OldCursor,WaitCursor: HCursor;
  json:String;
begin
  try
    WaitCursor:=LoadCursor(HINSTANCE,IDC_WAIT);
    OldCursor:=SetCursor(WaitCursor);
    nw := NetworkConfig;
    if Assigned(nw.AsArray) then
    begin
      DNSName := lowercase(UTF8Encode(nw.AsArray[0].S['dnshostname'] + '.' + nw.AsArray[0].S['dnsdomain']));
      UniqueString(DNSName);
      IP := lowercase(UTF8Encode(nw.AsArray[0]['ipaddress'].AsArray.S[0]));
      UniqueString(IP);
      //json := nw.AsJSon(True);
      //MessageBox(0,PChar(json),'dll',0);

      DNSResult := DNSAQuery(DNSName);
      if Assigned(DnsResult) and Assigned(DnsResult.AsArray) and (DnsResult.AsArray.Length>0) then
        Result := PChar(DNSName)
      else
        Result := PChar(IP);
    end
    else
    begin
      ip:= '';
      dnsname:='';
      Result := PChar(ip);
    end;
    //MessageBox(0,PChar(DNSName),'dll',0);
    //MessageBox(0,PChar(IP),'dll',0);

  finally
    SetCursor(OldCursor);
  end;
end;

function GetWaptServerOrComputerDNSNameOrIP:PChar; stdcall;
var
  WaptServerURL: String;
  url: TIdURI;
begin
  WaptServerURL:=WaptGuessedIniReadString('wapt_server','');
  if WaptServerURL<>'' then
  begin
    url := TIdURI.Create(WaptServerURL);
    try
      Result := PChar(url.Host);
    finally
      FreeAndNil(Url);
    end;
  end
  else
    Result := GetComputerDNSNameOrIP;
end;

exports
  GetComputerDNSName,
  GetComputerConnectedIP,
  GetComputerDNSNameOrIP,
  GetWaptServerOrComputerDNSNameOrIP;

end.

