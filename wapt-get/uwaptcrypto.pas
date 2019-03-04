unit uwaptcrypto;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, superobject, Variants;

function BinToStr(const Bin: array of byte): ansistring;
function SHA1Hash(FilePath: ansistring): ansistring;
function SHA256Hash(FilePath: ansistring): ansistring;

function VerifySHA256Files(FileHashes: String): String;

function CreateSignedCert(pywaptcrypto:Variant;
        keyfilename,
        crtbasename,
        destdir,
        country,
        locality,
        organization,
        orgunit,
        commonname,
        email,
        keypassword:String;
        codesigning:Boolean;
        IsCACert:Boolean;
        IsClientAuth:Boolean;
        CACertificateFilename:String='';
        CAKeyFilename:String='';
        CAKeyPassword:String=''
    ):String;

function RandomPassword(PLen: Integer): string;

type

  { TSigner }

  TSigner = class(TObject)
  private
    PrivateKey: Variant;
    PublicCertificate: Variant;

  public
    constructor Create(aPrivateKey: Variant; aPublicCertificate: Variant); overload;
    destructor Destroy; override;

    procedure SignAction(ActionDict: ISuperobject);
    procedure SignActions(ActionsList: ISuperobject);
    procedure SignPackage(PackageEntry: Variant);

  end;

  { TVerifier }

  TVerifier = class(TObject)
  private
    // to rebuild a cert chain
    KnownCertificates: Variant;
    //
    TrustedCertificates: Variant;

  public
    constructor Create(const aTrustedCertificates: Variant; const aKnownCertificates: Variant); overload;
    destructor Destroy; override;

    function CheckAction(ActionDict: ISuperobject; MaxAgeSecs: Integer=0): Variant;
    function CheckActions(ActionsList: ISuperObject; MaxAgeSecs: Integer=0
      ): Variant;
    function CheckPackage(PackageEntry: Variant): Variant;
    function CheckPackageControl(PackageEntry: Variant): Variant;

  end;


implementation

uses DCPsha1, DCPsha256,FileUtil, LazFileUtils, LazUTF8,VarPyth;

function BinToStr(const Bin: array of byte): ansistring;
const
  HexSymbols = '0123456789abcdef';
var
  i: integer;
begin
  SetLength(Result, 2 * Length(Bin));
  for i := 0 to Length(Bin) - 1 do
  begin
    Result[1 + 2 * i + 0] := HexSymbols[1 + Bin[i] shr 4];
    Result[1 + 2 * i + 1] := HexSymbols[1 + Bin[i] and $0F];
  end;
end;

function SHA1Hash(FilePath: ansistring): ansistring;
var
  Context: TDCP_sha1;
  Buf: PByte;
  BufSize, ReadSize, TotalSize: integer;
  FileStream: TFileStream;
  RawDigest: array[0..31] of byte;
begin
  Result := '';
  FileStream := nil;
  Buf := nil;
  Context := nil;

  TotalSize := 0;
  Bufsize := 32 * 1024; // 32k

  try
    FileStream := TFileStream.Create(FilePath, fmOpenRead);
    FileStream.Position := 0;
    Buf := GetMem(BufSize);
    Context := TDCP_sha1.Create(nil);
    Context.Init;

    while True do
    begin
      ReadSize := FileStream.Read(Buf^, BufSize);
      if ReadSize <= 0 then
        break;
      Context.Update(Buf^, ReadSize);
    end;

    Context.Final(RawDigest);

    Result := BinToStr(RawDigest);

  finally
    if FileStream <> nil then
      FileStream.Free;
    if Buf <> nil then
      FreeMem(Buf);
    if Context <> nil then
      Context.Free;
  end;
end;

function SHA256Hash(FilePath: ansistring): ansistring;
var
  Context: TDCP_sha256;
  Buf: PByte;
  BufSize, ReadSize, TotalSize: integer;
  FileStream: TFileStream;
  RawDigest: array[0..31] of byte;
begin
  Result := '';
  FileStream := nil;
  Buf := nil;
  Context := nil;

  TotalSize := 0;
  Bufsize := 32 * 1024; // 32k

  try
    FileStream := TFileStream.Create(FilePath, fmOpenRead);
    FileStream.Position := 0;
    Buf := GetMem(BufSize);
    Context := TDCP_sha256.Create(nil);
    Context.Init;

    while True do
    begin
      ReadSize := FileStream.Read(Buf^, BufSize);
      if ReadSize <= 0 then
        break;
      Context.Update(Buf^, ReadSize);
    end;

    Context.Final(RawDigest);

    Result := BinToStr(RawDigest);

  finally
    if FileStream <> nil then
      FileStream.Free;
    if Buf <> nil then
      FreeMem(Buf);
    if Context <> nil then
      Context.Free;
  end;
end;

function VerifySHA256Files(FileHashes: String): String;
begin

end;

function RandomPassword(PLen: Integer): string;
var
  str: string;
begin
  Randomize;
  //string with all possible chars
  str    := 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-/*@#!:,~';
  Result := '';
  repeat
    Result := Result + str[Random(Length(str)) + 1];
  until (Length(Result) = PLen)
end;

function CreateSignedCert(pywaptcrypto:Variant;
        keyfilename,
        crtbasename,
        destdir,
        country,
        locality,
        organization,
        orgunit,
        commonname,
        email,
        keypassword:String;
        codesigning:Boolean;
        IsCACert:Boolean;
        IsClientAuth:Boolean;
        CACertificateFilename:String='';
        CAKeyFilename:String='';
        CAKeyPassword:String=''

    ):String;
var
  vCAKeyFilename,vdestpem,vdestcrt,vCAKeyPassword : Variant;
  key,cert,cakey,cacert:Variant;
  ca_pem: String;

begin
  result := '';
  cacert := Null;
  cakey := Null;

  if (CACertificateFilename<>'') then
    if not FileExists(CACertificateFilename) then
      raise Exception.CreateFmt('CA Certificate %s does not exist',[CACertificateFilename])
    else
      cacert:= pywaptcrypto.SSLCertificate(crt_filename := CACertificateFilename);

  if (CAKeyFilename<>'') then
    if not FileExists(CAKeyFilename) then
      raise Exception.CreateFmt('CA private key %s does not exist',[CAKeyFilename])
    else
    begin
      if CAKeyPassword <> '' then
      begin
        vCAKeyFilename := UTF8Decode(CAKeyFilename);
        vCAKeyPassword := UTF8Decode(CAKeyPassword);
        cakey:= pywaptcrypto.SSLPrivateKey(filename := vCAKeyFilename, password := vCAKeyPassword);
      end
      else
        raise Exception.CreateFmt('No password for decryption of %s',[CAKeyFilename]);
    end;

  if FileExists(keyfilename) then
    vdestpem := UTF8Decode(keyfilename)
  else
  begin
    if ExtractFileNameOnly(keyfilename) = keyfilename then
      vdestpem := UTF8Decode(AppendPathDelim(destdir)+ExtractFileNameOnly(keyfilename)+'.pem')
    else
      vdestpem := UTF8Decode(keyfilename);
  end;

  if crtbasename = '' then
    crtbasename := ExtractFileNameOnly(keyfilename);

  vdestcrt := UTF8Decode(AppendPathDelim(destdir)+crtbasename+'.crt');
  if not DirectoryExists(destdir) then
    ForceDirectories(destdir);

  key := pywaptcrypto.SSLPrivateKey(filename := vdestpem,password := keypassword);

  // Create private key  if not already exist
  if not FileExistsUTF8(keyfilename) then
  begin
    key.create(bits := 2048);
    key.save_as_pem(password := keypassword)
  end;

  // None can not be passed... not accepted : invalid Variant type
  // using default None on the python side to workaround this...
  // python call
  if  VarIsNull(cacert) or VarIsNull(cakey) or VarIsEmpty(cacert) or VarIsEmpty(cakey) then
    // self signed
    cert := key.build_sign_certificate(
      cn :=  commonname,
      organization := organization,
      locality := locality,
      country := country,
      organizational_unit := orgunit,
      email := email,
      is_ca := IsCACert,
      is_code_signing := codesigning,
      is_client_auth := IsClientAuth)
  else
    cert := key.build_sign_certificate(
      ca_signing_key := cakey,
      ca_signing_cert := cacert,
      cn := commonname,
      organization := organization,
      locality := locality,
      country := country,
      organizational_unit := orgunit,
      email := email,
      is_ca := IsCACert,
      is_code_signing := codesigning,
      is_client_auth := IsClientAuth);

  cert.save_as_pem(filename := vdestcrt);

  if not VarIsNull(cacert) and not VarIsEmpty(cacert) then
    // append CA
    with TFileStream.Create(vdestcrt,fmOpenReadWrite) do
    try
      Seek(0,soEnd);
      ca_pem := VarToStr(cacert.as_pem('--noarg--'));
      WriteBuffer(ca_pem[1],length(ca_pem));
    finally
      Free;
    end;

  result := VarPythonAsString(vdestcrt);
end;

{ TSigner }

constructor TSigner.Create(aPrivateKey: Variant; aPublicCertificate: Variant);
begin

end;

destructor TSigner.Destroy;
begin
  inherited Destroy;
end;

procedure TSigner.SignAction(ActionDict: ISuperobject);
begin

end;

procedure TSigner.SignActions(ActionsList: ISuperobject);
begin

end;

procedure TSigner.SignPackage(PackageEntry: Variant);
begin

end;

{ TVerifier }

constructor TVerifier.Create(const aTrustedCertificates: Variant;
  const aKnownCertificates: Variant);
begin
  TrustedCertificates:=aTrustedCertificates;
  KnownCertificates:=aKnownCertificates;
end;

destructor TVerifier.Destroy;
begin
  inherited Destroy;
end;

function TVerifier.CheckAction(ActionDict: ISuperobject;MaxAgeSecs:Integer=0): Variant;
begin
end;

function TVerifier.CheckActions(ActionsList: ISuperObject;MaxAgeSecs:Integer=0): Variant;
begin
end;

function TVerifier.CheckPackage(PackageEntry: Variant): Variant;
begin
end;

function TVerifier.CheckPackageControl(PackageEntry: Variant): Variant;
begin
end;


end.

