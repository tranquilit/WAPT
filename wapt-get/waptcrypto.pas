unit waptcrypto;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

function BinToStr(const Bin: array of byte): ansistring;
function SHA1Hash(FilePath: ansistring): ansistring;
function SHA256Hash(FilePath: ansistring): ansistring;

function VerifySHA256Files(FileHashes: String): String;

implementation

uses DCPsha1, DCPsha256;

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

end.

