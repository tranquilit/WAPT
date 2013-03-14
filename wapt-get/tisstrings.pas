unit tisstrings;
{**************************************************************************************************}
{                                                                                                  }
{ Project JEDI Code Library (JCL)                                                                  }
{                                                                                                  }
{ The contents of this file are subject to the Mozilla Public License Version 1.1 (the "License"); }
{ you may not use this file except in compliance with the License. You may obtain a copy of the    }
{ License at http://www.mozilla.org/MPL/                                                           }
{                                                                                                  }
{ Software distributed under the License is distributed on an "AS IS" basis, WITHOUT WARRANTY OF   }
{ ANY KIND, either express or implied. See the License for the specific language governing rights  }
{ and limitations under the License.                                                               }
{                                                                                                  }
{ The Original Code is JclStrings.pas.                                                             }
{**************************************************************************************************}

{$mode objfpc}{$H+}
{$define UNICODE_RTL_DATABASE}
interface

uses
  Classes, SysUtils;

// Exceptions
type
  EJclStringError = class(Exception);

resourcestring
  RsBlankSearchString       = 'Search string cannot be blank';
  RsInvalidEmptyStringItem  = 'String list passed to StringsToMultiSz cannot contain empty strings.';
  RsNumericConstantTooLarge = 'Numeric constant too large (%d) at position %d.';
  RsFormatException         = 'Format exception';
  RsDotNetFormatNullFormat  = 'Format string is null';
  RsArgumentIsNull          = 'Argument %d is null';
  RsDotNetFormatArgumentNotSupported = 'Argument type of %d is not supported';
  RsArgumentOutOfRange      = 'Argument out of range';
  RsTabs_DuplicatesNotAllowed = 'Duplicate tab stops are not allowed.';
  RsTabs_StopExpected = 'A tab stop was expected but not found.';
  RsTabs_CloseBracketExpected = 'Closing bracket expected.';
  RsTabs_TabWidthExpected = 'Tab width expected.';
  // Default text for the NullReferenceException in .NET
  RsArg_NullReferenceException = 'Object reference not set to an instance of an object.';

  // Character constants and sets

  const
    // line delimiters for a version of Delphi/C++Builder
    NativeLineFeed       = Char(#10);
    NativeCarriageReturn = Char(#13);
    NativeCrLf           = string(#13#10);
    // default line break for a version of Delphi on a platform
    {$IFDEF MSWINDOWS}
    NativeLineBreak      = NativeCrLf;
    {$ENDIF MSWINDOWS}
    {$IFDEF UNIX}
    NativeLineBreak      = NativeLineFeed;
    {$ENDIF UNIX}

    HexPrefixPascal = string('$');
    HexPrefixC      = string('0x');
    HexDigitFmt32   = string('%.8x');
    HexDigitFmt64   = string('%.16x');

    {$IFDEF BCB}
    HexPrefix = HexPrefixC;
    {$ELSE ~BCB}
    HexPrefix = HexPrefixPascal;
    {$ENDIF ~BCB}

    {$IFDEF CPU32}
    HexDigitFmt = HexDigitFmt32;
    {$ENDIF CPU32}
    {$IFDEF CPU64}
    HexDigitFmt = HexDigitFmt64;
    {$ENDIF CPU64}

    HexFmt = HexPrefix + HexDigitFmt;


    // Misc. often used character definitions
    NativeNull = Char(#0);
    NativeSoh = Char(#1);
    NativeStx = Char(#2);
    NativeEtx = Char(#3);
    NativeEot = Char(#4);
    NativeEnq = Char(#5);
    NativeAck = Char(#6);
    NativeBell = Char(#7);
    NativeBackspace = Char(#8);
    NativeTab = Char(#9);
    NativeVerticalTab = Char(#11);
    NativeFormFeed = Char(#12);
    NativeSo = Char(#14);
    NativeSi = Char(#15);
    NativeDle = Char(#16);
    NativeDc1 = Char(#17);
    NativeDc2 = Char(#18);
    NativeDc3 = Char(#19);
    NativeDc4 = Char(#20);
    NativeNak = Char(#21);
    NativeSyn = Char(#22);
    NativeEtb = Char(#23);
    NativeCan = Char(#24);
    NativeEm = Char(#25);
    NativeEndOfFile = Char(#26);
    NativeEscape = Char(#27);
    NativeFs = Char(#28);
    NativeGs = Char(#29);
    NativeRs = Char(#30);
    NativeUs = Char(#31);
    NativeSpace = Char(' ');
    NativeComma = Char(',');
    NativeBackslash = Char('\');
    NativeForwardSlash = Char('/');

    NativeDoubleQuote = Char('"');
    NativeSingleQuote = Char('''');



type
  Float = Extended;
  TDynStringArray        = array of string;
  TCharValidator = function(const C: Char): Boolean;

  function ArrayContainsChar(const Chars: array of Char; const C: Char): Boolean; overload;
  function ArrayContainsChar(const Chars: array of Char; const C: Char; out Index: SizeInt): Boolean; overload;

// String Search and Replace Routines
function StrCharCount(const S: string; C: Char): SizeInt; overload;
function StrCharsCount(const S: string; const Chars: TCharValidator): SizeInt;
function StrCharsCount(const S: string; const Chars: array of Char): SizeInt; overload;
function StrStrCount(const S, SubS: string): SizeInt;
function StrCompare(const S1, S2: string; CaseSensitive: Boolean = False): SizeInt;
function StrCompareRange(const S1, S2: string; Index, Count: SizeInt; CaseSensitive: Boolean = True): SizeInt;
function StrCompareRangeEx(const S1, S2: string; Index, Count: SizeInt; CaseSensitive: Boolean): SizeInt;
procedure StrFillChar(var S; Count: SizeInt; C: Char);
function StrRepeatChar(C: Char; Count: SizeInt): string;
function StrFind(const Substr, S: string; const Index: SizeInt = 1): SizeInt;
function StrHasPrefix(const S: string; const Prefixes: array of string): Boolean;
function StrHasSuffix(const S: string; const Suffixes: array of string): Boolean;
function StrIndex(const S: string; const List: array of string; CaseSensitive: Boolean = False): SizeInt;
function StrIHasPrefix(const S: string; const Prefixes: array of string): Boolean;
function StrIHasSuffix(const S: string; const Suffixes: array of string): Boolean;
function StrILastPos(const SubStr, S: string): SizeInt;
function StrIPos(const SubStr, S: string): SizeInt;
function StrIPrefixIndex(const S: string; const Prefixes: array of string): SizeInt;
function StrIsOneOf(const S: string; const List: array of string): Boolean;
function StrISuffixIndex(const S: string; const Suffixes: array of string): SizeInt;
function StrLastPos(const SubStr, S: string): SizeInt;
function StrMatch(const Substr, S: string; Index: SizeInt = 1): SizeInt;
function StrMatches(const Substr, S: string; const Index: SizeInt = 1): Boolean;
function StrNIPos(const S, SubStr: string; N: SizeInt): SizeInt;
function StrNPos(const S, SubStr: string; N: SizeInt): SizeInt;
function StrPrefixIndex(const S: string; const Prefixes: array of string): SizeInt;
function StrSearch(const Substr, S: string; const Index: SizeInt = 1): SizeInt;
function StrSuffixIndex(const S: string; const Suffixes: array of string): SizeInt;


// String Transformation Routines
function StrCenter(const S: string; L: SizeInt; C: Char = ' '): string;
function StrCharPosLower(const S: string; CharPos: SizeInt): string;
function StrCharPosUpper(const S: string; CharPos: SizeInt): string;
function StrDoubleQuote(const S: string): string;
function StrEnsureNoPrefix(const Prefix, Text: string): string;
function StrEnsureNoSuffix(const Suffix, Text: string): string;
function StrEnsurePrefix(const Prefix, Text: string): string;
function StrEnsureSuffix(const Suffix, Text: string): string;
function StrEscapedToString(const S: string): string;
procedure StrMove(var Dest: string; const Source: string; const ToIndex,
  FromIndex, Count: SizeInt);
function StrPadLeft(const S: string; Len: SizeInt; C: Char = NativeSpace): string;
function StrPadRight(const S: string; Len: SizeInt; C: Char = NativeSpace): string;
function StrProper(const S: string): string;
function StrQuote(const S: string; C: Char): string;
function StrRemoveChars(const S: string; const Chars: TCharValidator): string; overload;
function StrRemoveChars(const S: string; const Chars: array of Char): string; overload;
function StrRemoveLeadingChars(const S: string; const Chars: TCharValidator): string; overload;
function StrRemoveLeadingChars(const S: string; const Chars: array of Char): string; overload;
function StrRemoveEndChars(const S: string; const Chars: TCharValidator): string; overload;
function StrRemoveEndChars(const S: string; const Chars: array of Char): string; overload;
function StrKeepChars(const S: string; const Chars: TCharValidator): string; overload;
function StrKeepChars(const S: string; const Chars: array of Char): string; overload;
procedure StrReplace(var S: string; const Search, Replace: string; Flags: TReplaceFlags = []);
function StrReplaceChar(const S: string; const Source, Replace: Char): string;
function StrReplaceChars(const S: string; const Chars: TCharValidator; Replace: Char): string; overload;
function StrReplaceChars(const S: string; const Chars: array of Char; Replace: Char): string; overload;
function StrReplaceButChars(const S: string; const Chars: TCharValidator; Replace: Char): string; overload;
function StrReplaceButChars(const S: string; const Chars: array of Char; Replace: Char): string; overload;
function StrRepeat(const S: string; Count: SizeInt): string;
function StrReverse(const S: string): string;
procedure StrReverseInPlace(var S: string);
function StrSingleQuote(const S: string): string;
procedure StrSkipChars(var S: PChar; const Chars: TCharValidator); overload;
procedure StrSkipChars(var S: PChar; const Chars: array of Char); overload;
procedure StrSkipChars(const S: string; var Index: SizeInt; const Chars: TCharValidator); overload;
procedure StrSkipChars(const S: string; var Index: SizeInt; const Chars: array of Char); overload;
function StrSmartCase(const S: string; const Delimiters: array of Char): string; overload;
function StrStringToEscaped(const S: string): string;
function StrStripNonNumberChars(const S: string): string;
function StrToHex(const Source: string): string;
function StrTrimCharLeft(const S: string; C: Char): string;
function StrTrimCharsLeft(const S: string; const Chars: TCharValidator): string; overload;
function StrTrimCharsLeft(const S: string; const Chars: array of Char): string; overload;
function StrTrimCharRight(const S: string; C: Char): string;
function StrTrimCharsRight(const S: string; const Chars: TCharValidator): string; overload;
function StrTrimCharsRight(const S: string; const Chars: array of Char): string; overload;
function StrTrimQuotes(const S: string): string;


// String Extraction
// Returns the String before SubStr
function StrAfter(const SubStr, S: string): string;
/// Returns the string after SubStr
function StrBefore(const SubStr, S: string): string;
/// Splits a string at SubStr, returns true when SubStr is found, Left contains the
/// string before the SubStr and Rigth the string behind SubStr
function StrSplit(const SubStr, S: string;var Left, Right : string): boolean;
/// Returns the string between Start and Stop
function StrBetween(const S: string; const Start, Stop: Char): string;
/// Returns the left N characters of the string
function StrChopRight(const S: string; N: SizeInt): string;
/// Returns the left Count characters of the string
function StrLeft(const S: string; Count: SizeInt): string;
/// Returns the string starting from position Start for the Count Characters
function StrMid(const S: string; Start, Count: SizeInt): string;
/// Returns the string starting from position N to the end
function StrRestOf(const S: string; N: SizeInt): string;
/// Returns the right Count characters of the string
function StrRight(const S: string; Count: SizeInt): string;

function FileToString(const FileName: string): {$IFDEF COMPILER12_UP}RawByteString{$ELSE}AnsiString{$ENDIF};
procedure StringToFile(const FileName: string; const Contents: {$IFDEF COMPILER12_UP}RawByteString{$ELSE}AnsiString{$ENDIF};
  Append: Boolean = False);

function StrToken(var S: string; Separator: Char): string;
procedure StrTokens(const S: string; const List: TStrings);
procedure StrTokenToStrings(S: string; Separator: Char; const List: TStrings);
function StrWord(const S: string; var Index: SizeInt; out Word: string): Boolean; overload;
function StrWord(var S: PChar; out Word: string): Boolean; overload;
function StrIdent(const S: string; var Index: SizeInt; out Ident: string): Boolean; overload;
function StrIdent(var S: PChar; out Ident: string): Boolean; overload;

function ArrayOf(List: TStrings): TDynStringArray; overload;

// Character Test Routines
function CharEqualNoCase(const C1, C2: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsAlpha(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsAlphaNum(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsBlank(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsControl(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsDelete(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsDigit(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsFracDigit(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsHexDigit(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsLower(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsNumberChar(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} {$IFDEF COMPILER16_UP} inline; {$ENDIF} {$ENDIF}
function CharIsNumber(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} {$IFDEF COMPILER16_UP} inline; {$ENDIF} {$ENDIF}
function CharIsPrintable(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsPunctuation(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsReturn(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsSpace(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsUpper(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsValidIdentifierLetter(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsWhiteSpace(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharIsWildcard(const C: Char): Boolean; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}


// Character Search and Replace
function CharPos(const S: string; const C: Char; const Index: SizeInt = 1): SizeInt;
function CharLastPos(const S: string; const C: Char; const Index: SizeInt = 1): SizeInt;
function CharIPos(const S: string; C: Char; const Index: SizeInt = 1): SizeInt;
function CharReplace(var S: string; const Search, Replace: Char): SizeInt;


// Character Transformation Routines
function CharHex(const C: Char): Byte;
function CharLower(const C: Char): Char; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharUpper(const C: Char): Char; {$IFDEF SUPPORTS_INLINE} inline; {$ENDIF}
function CharToggleCase(const C: Char): Char;



implementation

uses character;

function ArrayContainsChar(const Chars: array of Char; const C: Char): Boolean;
var
  idx: SizeInt;
begin
  Result := ArrayContainsChar(Chars, C, idx);
end;

function ArrayContainsChar(const Chars: array of Char; const C: Char; out Index: SizeInt): Boolean;
{ optimized version for sorted arrays
var
  I, L, H: SizeInt;
begin
  L := Low(Chars);
  H := High(Chars);
  while L <= H do
  begin
    I := (L + H) div 2;
    if C = Chars[I] then
    begin
      Result := True;
      Exit;
    end
    else
    if C < Chars[I] then
      H := I - 1
    else
      // C > Chars[I]
      L := I + 1;
  end;
  Result := False;
end;}
begin
  Index := High(Chars);
  while (Index >= Low(Chars)) and (Chars[Index] <> C) do
    Dec(Index);
  Result := Index >= Low(Chars);
end;


//=== String Search and Replace Routines =====================================



function StrCharCount(const S: string; C: Char): SizeInt;
var
  I: SizeInt;
begin
  Result := 0;
  for I := 1 to Length(S) do
    if S[I] = C then
      Inc(Result);
end;

function StrCharsCount(const S: string; const Chars: TCharValidator): SizeInt;
var
  I: SizeInt;
begin
  Result := 0;
  for I := 1 to Length(S) do
    if Chars(S[I]) then
      Inc(Result);
end;

function StrCharsCount(const S: string; const Chars: array of Char): SizeInt;
var
  I: SizeInt;
begin
  Result := 0;
  for I := 1 to Length(S) do
    if ArrayContainsChar(Chars, S[I]) then
      Inc(Result);
end;

function StrStrCount(const S, SubS: string): SizeInt;
var
  I: SizeInt;
begin
  Result := 0;
  if (Length(SubS) > Length(S)) or (Length(SubS) = 0) or (Length(S) = 0) then
    Exit;
  if Length(SubS) = 1 then
  begin
    Result := StrCharCount(S, SubS[1]);
    Exit;
  end;
  I := StrSearch(SubS, S, 1);

  if I > 0 then
    Inc(Result);

  while (I > 0) and (Length(S) > I + Length(SubS)) do
  begin
    I := StrSearch(SubS, S, I + 1);

    if I > 0 then
      Inc(Result);
  end;
end;

(*
{ 1}  Test(StrCompareRange('', '', 1, 5), 0);
{ 2}  Test(StrCompareRange('A', '', 1, 5), -1);
{ 3}  Test(StrCompareRange('AB', '', 1, 5), -1);
{ 4}  Test(StrCompareRange('ABC', '', 1, 5), -1);
{ 5}  Test(StrCompareRange('', 'A', 1, 5), -1);
{ 6}  Test(StrCompareRange('', 'AB',  1, 5), -1);
{ 7}  Test(StrCompareRange('', 'ABC', 1, 5), -1);
{ 8}  Test(StrCompareRange('A', 'a', 1, 5), -2);
{ 9}  Test(StrCompareRange('A', 'a', 1, 1), -32);
{10}  Test(StrCompareRange('aA', 'aB', 1, 1), 0);
{11}  Test(StrCompareRange('aA', 'aB', 1, 2), -1);
{12}  Test(StrCompareRange('aB', 'aA', 1, 2), 1);
{13}  Test(StrCompareRange('aA', 'aa', 1, 2), -32);
{14}  Test(StrCompareRange('aa', 'aA', 1, 2), 32);
{15}  Test(StrCompareRange('', '', 1, 0), 0);
{16}  Test(StrCompareRange('A', 'A', 1, 0), -2);
{17}  Test(StrCompareRange('Aa', 'A', 1, 0), -2);
{18}  Test(StrCompareRange('Aa', 'Aa', 1, 2), 0);
{19}  Test(StrCompareRange('Aa', 'A', 1, 2), 0);
{20}  Test(StrCompareRange('Ba', 'A', 1, 2), 1);
*)
function StrCompareRangeEx(const S1, S2: string; Index, Count: SizeInt; CaseSensitive: Boolean): SizeInt;
var
  Len1, Len2: SizeInt;
  I: SizeInt;
  C1, C2: Char;
begin
  if Pointer(S1) = Pointer(S2) then
  begin
    if (Count <= 0) and (S1 <> '') then
      Result := -2 // no work
    else
      Result := 0;
  end
  else
  if (S1 = '') or (S2 = '') then
    Result := -1 // null string
  else
  if Count <= 0 then
    Result := -2 // no work
  else
  begin
    Len1 := Length(S1);
    Len2 := Length(S2);

    if (Index - 1) + Count > Len1 then
      Result := -2
    else
    begin
      if (Index - 1) + Count > Len2 then // strange behaviour, but the assembler code does it
        Count := Len2 - (Index - 1);

      if CaseSensitive then
      begin
        for I := 0 to Count - 1 do
        begin
          C1 := S1[Index + I];
          C2 := S2[Index + I];
          if C1 <> C2 then
          begin
            Result := Ord(C1) - Ord(C2);
            Exit;
          end;
        end;
      end
      else
      begin
        for I := 0 to Count - 1 do
        begin
          C1 := S1[Index + I];
          C2 := S2[Index + I];
          if C1 <> C2 then
          begin
            C1 := CharLower(C1);
            C2 := CharLower(C2);
            if C1 <> C2 then
            begin
              Result := Ord(C1) - Ord(C2);
              Exit;
            end;
          end;
        end;
      end;
      Result := 0;
    end;
  end;
end;

function StrCompare(const S1, S2: string; CaseSensitive: Boolean): SizeInt;
var
  Len1, Len2: SizeInt;
begin
  if Pointer(S1) = Pointer(S2) then
    Result := 0
  else
  begin
    Len1 := Length(S1);
    Len2 := Length(S2);
    Result := Len1 - Len2;
    if Result = 0 then
      Result := StrCompareRangeEx(S1, S2, 1, Len1, CaseSensitive);
  end;
end;

function StrCompareRange(const S1, S2: string; Index, Count: SizeInt; CaseSensitive: Boolean): SizeInt;
begin
  Result := StrCompareRangeEx(S1, S2, Index, Count, CaseSensitive);
end;

procedure StrFillChar(var S; Count: SizeInt; C: Char);
{$IFDEF SUPPORTS_UNICODE}
asm
        // 32 --> EAX S
        //        EDX Count
        //        ECX C
        // 64 --> RCX S
        //        RDX Count
        //        R8W C
        {$IFDEF CPU32}
        DEC     EDX
        JS      @@Leave
@@Loop:
        MOV     [EAX], CX
        ADD     EAX, 2
        DEC     EDX
        JNS     @@Loop
        {$ENDIF CPU32}
        {$IFDEF CPU64}
        DEC     RDX
        JS      @@Leave
@@Loop:
        MOV     WORD PTR [RCX], R8W
        ADD     RCX, 2
        DEC     RDX
        JNS     @@Loop
        {$ENDIF CPU64}
@@Leave:
end;
{$ELSE ~SUPPORTS_UNICODE}
begin
  if Count > 0 then
    FillChar(S, Count, C);
end;
{$ENDIF ~SUPPORTS_UNICODE}

function StrRepeatChar(C: Char; Count: SizeInt): string;
begin
  SetLength(Result, Count);
  if Count > 0 then
    StrFillChar(Result[1], Count, C);
end;

function StrFind(const Substr, S: string; const Index: SizeInt): SizeInt;
var
  pos: SizeInt;
begin
  if (SubStr <> '') and (S <> '') then
  begin
    pos := StrIPos(Substr, Copy(S, Index, Length(S) - Index + 1));
    if pos = 0 then
      Result := 0
    else
      Result := Index + Pos - 1;
  end
  else
    Result := 0;
end;

function StrHasPrefix(const S: string; const Prefixes: array of string): Boolean;
begin
  Result := StrPrefixIndex(S, Prefixes) > -1;
end;

function StrHasSuffix(const S: string; const Suffixes: array of string): Boolean;
begin
  Result := StrSuffixIndex(S, Suffixes) > -1;
end;

function StrIndex(const S: string; const List: array of string; CaseSensitive: Boolean): SizeInt;
var
  I: SizeInt;
begin
  Result := -1;
  for I := Low(List) to High(List) do
  begin
    if StrCompare(S, List[I], CaseSensitive) = 0 then
    begin
      Result := I;
      Break;
    end;
  end;
end;

function StrIHasPrefix(const S: string; const Prefixes: array of string): Boolean;
begin
  Result := StrIPrefixIndex(S, Prefixes) > -1;
end;

function StrIHasSuffix(const S: string; const Suffixes: array of string): Boolean;
begin
  Result := StrISuffixIndex(S, Suffixes) > -1;
end;

function StrILastPos(const SubStr, S: string): SizeInt;
begin
  Result := StrLastPos(StrUpper(PChar(SubStr)), StrUpper(PChar(S)));
end;

function StrIPos(const SubStr, S: string): SizeInt;
begin
  Result := Pos(StrUpper(PChar(SubStr)), StrUpper(PChar(S)));
end;

function StrIPrefixIndex(const S: string; const Prefixes: array of string): SizeInt;
var
  I: SizeInt;
  Test: string;
begin
  Result := -1;
  for I := Low(Prefixes) to High(Prefixes) do
  begin
    Test := StrLeft(S, Length(Prefixes[I]));
    if CompareText(Test, Prefixes[I]) = 0 then
    begin
      Result := I;
      Break;
    end;
  end;
end;

function StrIsOneOf(const S: string; const List: array of string): Boolean;
begin
  Result := StrIndex(S, List) > -1;
end;

function StrISuffixIndex(const S: string; const Suffixes: array of string): SizeInt;
var
  I: SizeInt;
  Test: string;
begin
  Result := -1;
  for I := Low(Suffixes) to High(Suffixes) do
  begin
    Test := StrRight(S, Length(Suffixes[I]));
    if CompareText(Test, Suffixes[I]) = 0 then
    begin
      Result := I;
      Break;
    end;
  end;
end;

function StrLastPos(const SubStr, S: string): SizeInt;
var
  Last, Current: PChar;
begin
  Result := 0;
  Last := nil;
  Current := PChar(S);

  while (Current <> nil) and (Current^ <> #0) do
  begin
    Current := StrPos(PChar(Current), PChar(SubStr));
    if Current <> nil then
    begin
      Last := Current;
      Inc(Current);
    end;
  end;
  if Last <> nil then
    Result := Abs(PChar(S) - Last) + 1;
end;

// IMPORTANT NOTE: The StrMatch function does currently not work with the Asterix (*)
// (*) acts like (?)

function StrMatch(const Substr, S: string; Index: SizeInt): SizeInt;
var
  SI, SubI, SLen, SubLen: SizeInt;
  SubC: Char;
begin
  SLen := Length(S);
  SubLen := Length(Substr);
  Result := 0;
  if (Index > SLen) or (SubLen = 0) then
    Exit;
  while Index <= SLen do
  begin
    SubI := 1;
    SI := Index;
    while (SI <= SLen) and (SubI <= SubLen) do
    begin
      SubC := Substr[SubI];
      if (SubC = '*') or (SubC = '?') or (SubC = S[SI]) then
      begin
        Inc(SI);
        Inc(SubI);
      end
      else
        Break;
    end;
    if SubI > SubLen then
    begin
      Result := Index;
      Break;
    end;
    Inc(Index);
  end;
end;

// Derived from "Like" by Michael Winter
function StrMatches(const Substr, S: string; const Index: SizeInt): Boolean;
var
  StringPtr: PChar;
  PatternPtr: PChar;
  StringRes: PChar;
  PatternRes: PChar;
begin
  if SubStr = '' then
    raise EJclStringError.CreateRes(@RsBlankSearchString);

  Result := SubStr = '*';

  if Result or (S = '') then
    Exit;

  if (Index <= 0) or (Index > Length(S)) then
    raise EJclStringError.CreateRes(@RsArgumentOutOfRange);

  StringPtr := PChar(@S[Index]);
  PatternPtr := PChar(SubStr);
  StringRes := nil;
  PatternRes := nil;

  repeat
    repeat
      case PatternPtr^ of
        #0:
        begin
          Result := StringPtr^ = #0;
          if Result or (StringRes = nil) or (PatternRes = nil) then
            Exit;

          StringPtr := StringRes;
          PatternPtr := PatternRes;
          Break;
        end;
        '*':
        begin
          Inc(PatternPtr);
          PatternRes := PatternPtr;
          Break;
        end;
        '?':
        begin
          if StringPtr^ = #0 then
            Exit;
          Inc(StringPtr);
          Inc(PatternPtr);
        end;
      else
      begin
        if StringPtr^ = #0 then
          Exit;
        if StringPtr^ <> PatternPtr^ then
        begin
          if (StringRes = nil) or (PatternRes = nil) then
            Exit;
          StringPtr := StringRes;
          PatternPtr := PatternRes;
          Break;
        end
        else
        begin
          Inc(StringPtr);
          Inc(PatternPtr);
        end;
      end;
      end;
    until False;

    repeat
      case PatternPtr^ of
        #0:
        begin
          Result := True;
          Exit;
        end;
        '*':
        begin
          Inc(PatternPtr);
          PatternRes := PatternPtr;
        end;
        '?':
        begin
          if StringPtr^ = #0 then
            Exit;
          Inc(StringPtr);
          Inc(PatternPtr);
        end;
      else
      begin
        repeat
          if StringPtr^ = #0 then
            Exit;
          if StringPtr^ = PatternPtr^ then
            Break;
          Inc(StringPtr);
        until False;
        Inc(StringPtr);
        StringRes := StringPtr;
        Inc(PatternPtr);
        Break;
      end;
      end;
    until False;
  until False;
end;

function StrNPos(const S, SubStr: string; N: SizeInt): SizeInt;
var
  I, P: SizeInt;
begin
  if N < 1 then
  begin
    Result := 0;
    Exit;
  end;

  Result := StrSearch(SubStr, S, 1);
  I := 1;
  while I < N do
  begin
    P := StrSearch(SubStr, S, Result + 1);
    if P = 0 then
    begin
      Result := 0;
      Break;
    end
    else
    begin
      Result := P;
      Inc(I);
    end;
  end;
end;

function StrNIPos(const S, SubStr: string; N: SizeInt): SizeInt;
var
  I, P: SizeInt;
begin
  if N < 1 then
  begin
    Result := 0;
    Exit;
  end;

  Result := StrFind(SubStr, S, 1);
  I := 1;
  while I < N do
  begin
    P := StrFind(SubStr, S, Result + 1);
    if P = 0 then
    begin
      Result := 0;
      Break;
    end
    else
    begin
      Result := P;
      Inc(I);
    end;
  end;
end;

function StrPrefixIndex(const S: string; const Prefixes: array of string): SizeInt;
var
  I: SizeInt;
  Test: string;
begin
  Result := -1;
  for I := Low(Prefixes) to High(Prefixes) do
  begin
    Test := StrLeft(S, Length(Prefixes[I]));
    if CompareStr(Test, Prefixes[I]) = 0 then
    begin
      Result := I;
      Break;
    end;
  end;
end;

function StrSearch(const Substr, S: string; const Index: SizeInt): SizeInt;
var
  SP, SPI, SubP: PChar;
  SLen: SizeInt;
begin
  SLen := Length(S);
  if Index <= SLen then
  begin
    SP := PChar(S);
    SubP := PChar(Substr);
    SPI := SP;
    Inc(SPI, Index);
    Dec(SPI);
    SPI := StrPos(SPI, SubP);
    if SPI <> nil then
      Result := SPI - SP + 1
    else
      Result := 0;
  end
  else
    Result := 0;
end;

function StrSuffixIndex(const S: string; const Suffixes: array of string): SizeInt;
var
  I: SizeInt;
  Test: string;
begin
  Result := -1;
  for I := Low(Suffixes) to High(Suffixes) do
  begin
    Test := StrRight(S, Length(Suffixes[I]));
    if CompareStr(Test, Suffixes[I]) = 0 then
    begin
      Result := I;
      Break;
    end;
  end;
end;



//=== String Transformation Routines =========================================

function StrCenter(const S: string; L: SizeInt; C: Char = ' '): string;
begin
  if Length(S) < L then
  begin
    Result := StringOfChar(C, (L - Length(S)) div 2) + S;
    Result := Result + StringOfChar(C, L - Length(Result));
  end
  else
    Result := S;
end;

function StrCharPosLower(const S: string; CharPos: SizeInt): string;
begin
  Result := S;
  if (CharPos > 0) and (CharPos <= Length(S)) then
    Result[CharPos] := CharLower(Result[CharPos]);
end;

function StrCharPosUpper(const S: string; CharPos: SizeInt): string;
begin
  Result := S;
  if (CharPos > 0) and (CharPos <= Length(S)) then
    Result[CharPos] := CharUpper(Result[CharPos]);
end;

function StrDoubleQuote(const S: string): string;
begin
  Result := NativeDoubleQuote + S + NativeDoubleQuote;
end;

function StrEnsureNoPrefix(const Prefix, Text: string): string;
var
  PrefixLen: SizeInt;
begin
  PrefixLen := Length(Prefix);
  if Copy(Text, 1, PrefixLen) = Prefix then
    Result := Copy(Text, PrefixLen + 1, Length(Text))
  else
    Result := Text;
end;

function StrEnsureNoSuffix(const Suffix, Text: string): string;
var
  SuffixLen: SizeInt;
  StrLength: SizeInt;
begin
  SuffixLen := Length(Suffix);
  StrLength := Length(Text);
  if Copy(Text, StrLength - SuffixLen + 1, SuffixLen) = Suffix then
    Result := Copy(Text, 1, StrLength - SuffixLen)
  else
    Result := Text;
end;

function StrEnsurePrefix(const Prefix, Text: string): string;
var
  PrefixLen: SizeInt;
begin
  PrefixLen := Length(Prefix);
  if Copy(Text, 1, PrefixLen) = Prefix then
    Result := Text
  else
    Result := Prefix + Text;
end;

function StrEnsureSuffix(const Suffix, Text: string): string;
var
  SuffixLen: SizeInt;
begin
  SuffixLen := Length(Suffix);
  if Copy(Text, Length(Text) - SuffixLen + 1, SuffixLen) = Suffix then
    Result := Text
  else
    Result := Text + Suffix;
end;

function StrEscapedToString(const S: string): string;
  procedure HandleHexEscapeSeq(const S: string; var I: SizeInt; Len: SizeInt; var Dest: string);
  const
    HexDigits = string('0123456789abcdefABCDEF');
  var
    StartI, Val, N: SizeInt;
  begin
    StartI := I;
    N := Pos(S[I + 1], HexDigits) - 1;
    if N < 0 then
      // '\x' without hex digit following is not escape sequence
      Dest := Dest + '\x'
    else
    begin
      Inc(I); // Jump over x
      if N >= 16 then
        N := N - 6;
      Val := N;
      // Same for second digit
      if I < Len then
      begin
        N := Pos(S[I + 1], HexDigits) - 1;
        if N >= 0 then
        begin
          Inc(I); // Jump over first digit
          if N >= 16 then
            N := N - 6;
          Val := Val * 16 + N;
        end;
      end;

      if Val > Ord(High(Char)) then
        raise EJclStringError.CreateResFmt(@RsNumericConstantTooLarge, [Val, StartI]);

      Dest := Dest + Char(Val);
    end;
  end;

  procedure HandleOctEscapeSeq(const S: string; var I: SizeInt; Len: SizeInt; var Dest: string);
  const
    OctDigits = string('01234567');
  var
    StartI, Val, N: SizeInt;
  begin
    StartI := I;
    // first digit
    Val := Pos(S[I], OctDigits) - 1;
    if I < Len then
    begin
      N := Pos(S[I + 1], OctDigits) - 1;
      if N >= 0 then
      begin
        Inc(I);
        Val := Val * 8 + N;
      end;
      if I < Len then
      begin
        N := Pos(S[I + 1], OctDigits) - 1;
        if N >= 0 then
        begin
          Inc(I);
          Val := Val * 8 + N;
        end;
      end;
    end;

    if Val > Ord(High(Char)) then
      raise EJclStringError.CreateResFmt(@RsNumericConstantTooLarge, [Val, StartI]);

    Dest := Dest + Char(Val);
  end;

var
  I, Len: SizeInt;
begin
  Result := '';
  I := 1;
  Len := Length(S);
  while I <= Len do
  begin
    if not ((S[I] = '\') and (I < Len)) then
      Result := Result + S[I]
    else
    begin
      Inc(I); // Jump over escape character
      case S[I] of
        'a':
          Result := Result + NativeBell;
        'b':
          Result := Result + NativeBackspace;
        'f':
          Result := Result + NativeFormFeed;
        'n':
          Result := Result + NativeLineFeed;
        'r':
          Result := Result + NativeCarriageReturn;
        't':
          Result := Result + NativeTab;
        'v':
          Result := Result + NativeVerticalTab;
        '\':
          Result := Result + '\';
        '"':
          Result := Result + '"';
        '''':
          Result := Result + ''''; // Optionally escaped
        '?':
          Result := Result + '?';  // Optionally escaped
        'x':
          if I < Len then
            // Start of hex escape sequence
            HandleHexEscapeSeq(S, I, Len, Result)
          else
            // '\x' at end of string is not escape sequence
            Result := Result + '\x';
        '0'..'7':
          // start of octal escape sequence
          HandleOctEscapeSeq(S, I, Len, Result);
      else
        // no escape sequence
        Result := Result + '\' + S[I];
      end;
    end;
    Inc(I);
  end;
end;

procedure StrMove(var Dest: string; const Source: string;
  const ToIndex, FromIndex, Count: SizeInt);
begin
  // Check strings
  if (Source = '') or (Length(Dest) = 0) then
    Exit;

  // Check FromIndex
  if (FromIndex <= 0) or (FromIndex > Length(Source)) or
    (ToIndex <= 0) or (ToIndex > Length(Dest)) or
    ((FromIndex + Count - 1) > Length(Source)) or ((ToIndex + Count - 1) > Length(Dest)) then
     { TODO : Is failure without notice the proper thing to do here? }
    Exit;

  // Move
  Move(Source[FromIndex], Dest[ToIndex], Count * SizeOf(Char));
end;

function StrPadLeft(const S: string; Len: SizeInt; C: Char): string;
var
  L: SizeInt;
begin
  L := Length(S);
  if L < Len then
    Result := StringOfChar(C, Len - L) + S
  else
    Result := S;
end;

function StrPadRight(const S: string; Len: SizeInt; C: Char): string;
var
  L: SizeInt;
begin
  L := Length(S);
  if L < Len then
    Result := S + StringOfChar(C, Len - L)
  else
    Result := S;
end;

function StrProper(const S: string): string;
begin
  Result := StrLower(pchar(S));
  if Result <> '' then
    Result[1] := UpCase(Result[1]);
end;

function StrQuote(const S: string; C: Char): string;
var
  L: SizeInt;
begin
  L := Length(S);
  Result := S;
  if L > 0 then
  begin
    if Result[1] <> C then
    begin
      Result := C + Result;
      Inc(L);
    end;
    if Result[L] <> C then
      Result := Result + C;
  end;
end;

function StrRemoveChars(const S: string; const Chars: TCharValidator): string;
var
  Source, Dest: PChar;
  Len, Index:   SizeInt;
begin
  Len := Length(S);
  SetLength(Result, Len);
  UniqueString(Result);
  Source := PChar(S);
  Dest := PChar(Result);
  for Index := 0 to Len - 1 do
  begin
    if not Chars(Source^) then
    begin
      Dest^ := Source^;
      Inc(Dest);
    end;
    Inc(Source);
  end;
  SetLength(Result, Dest - PChar(Result));
end;

function StrRemoveChars(const S: string; const Chars: array of Char): string;
var
  Source, Dest: PChar;
  Len, Index:   SizeInt;
begin
  Len := Length(S);
  SetLength(Result, Len);
  UniqueString(Result);
  Source := PChar(S);
  Dest := PChar(Result);
  for Index := 0 to Len - 1 do
  begin
    if not ArrayContainsChar(Chars, Source^) then
    begin
      Dest^ := Source^;
      Inc(Dest);
    end;
    Inc(Source);
  end;
  SetLength(Result, Dest - PChar(Result));
end;

function StrRemoveLeadingChars(const S: string; const Chars: TCharValidator): string;
var
  Len : SizeInt;
  I: SizeInt;
begin
  Len := Length(S);
  I := 1;
  while (I <= Len) and Chars(s[I]) do
    Inc(I);
  Result := Copy (s, I, Len-I+1);
end;

function StrRemoveLeadingChars(const S: string; const Chars: array of Char): string;
var
  Len : SizeInt;
  I: SizeInt;
begin
  Len := Length(S);
  I := 1;
  while (I <= Len) and ArrayContainsChar(Chars, s[I]) do
    Inc(I);
  Result := Copy (s, I, Len-I+1);
end;

function StrRemoveEndChars(const S: string; const Chars: TCharValidator): string;
var
  Len :   SizeInt;
begin
  Len := Length(S);
  while (Len > 0) and Chars(s[Len]) do
    Dec(Len);
  Result := Copy (s, 1, Len);
end;

function StrRemoveEndChars(const S: string; const Chars: array of Char): string;
var
  Len :   SizeInt;
begin
  Len := Length(S);
  while (Len > 0) and ArrayContainsChar(Chars, s[Len]) do
    Dec(Len);
  Result := Copy (s, 1, Len);
end;

function StrKeepChars(const S: string; const Chars: TCharValidator): string;
var
  Source, Dest: PChar;
  Len, Index:   SizeInt;
begin
  Len := Length(S);
  SetLength(Result, Len);
  UniqueString(Result);
  Source := PChar(S);
  Dest := PChar(Result);
  for Index := 0 to Len - 1 do
  begin
    if Chars(Source^) then
    begin
      Dest^ := Source^;
      Inc(Dest);
    end;
    Inc(Source);
  end;
  SetLength(Result, Dest - PChar(Result));
end;

function StrKeepChars(const S: string; const Chars: array of Char): string;
var
  Source, Dest: PChar;
  Len, Index:   SizeInt;
begin
  Len := Length(S);
  SetLength(Result, Len);
  UniqueString(Result);
  Source := PChar(S);
  Dest := PChar(Result);
  for Index := 0 to Len - 1 do
  begin
    if ArrayContainsChar(Chars, Source^) then
    begin
      Dest^ := Source^;
      Inc(Dest);
    end;
    Inc(Source);
  end;
  SetLength(Result, Dest - PChar(Result));
end;

function StrRepeat(const S: string; Count: SizeInt): string;
var
  Len, Index: SizeInt;
  Dest, Source: PChar;
begin
  Len := Length(S);
  SetLength(Result, Count * Len);
  Dest := PChar(Result);
  Source := PChar(S);
  if Dest <> nil then
    for Index := 0 to Count - 1 do
    begin
      Move(Source^, Dest^, Len * SizeOf(Char));
      Inc(Dest, Len);
    end;
end;

procedure StrReplace(var S: string; const Search, Replace: string; Flags: TReplaceFlags);
var
  SearchStr: string;
  ResultStr: string; { result string }
  SourcePtr: PChar;      { pointer into S of character under examination }
  SourceMatchPtr: PChar; { pointers into S and Search when first character has }
  SearchMatchPtr: PChar; { been matched and we're probing for a complete match }
  ResultPtr: PChar;      { pointer into Result of character being written }
  ResultIndex,
  SearchLength,          { length of search string }
  ReplaceLength,         { length of replace string }
  BufferLength,          { length of temporary result buffer }
  ResultLength: SizeInt; { length of result string }
  C: Char;               { first character of search string }
  IgnoreCase: Boolean;
begin
  if Search = '' then
  begin
    if S = '' then
    begin
      S := Replace;
      Exit;
    end
    else
      raise EJclStringError.CreateRes(@RsBlankSearchString);
  end;

  if S <> '' then
  begin
    IgnoreCase := rfIgnoreCase in Flags;
    if IgnoreCase then
      SearchStr := StrUpper(pchar(Search))
    else
      SearchStr := Search;
    { avoid having to call Length() within the loop }
    SearchLength := Length(Search);
    ReplaceLength := Length(Replace);
    ResultLength := Length(S);
    BufferLength := ResultLength;
    SetLength(ResultStr, BufferLength);
    { get pointers to begin of source and result }
    ResultPtr := PChar(ResultStr);
    SourcePtr := PChar(S);
    C := SearchStr[1];
    { while we haven't reached the end of the string }
    while True do
    begin
      { copy characters until we find the first character of the search string }
      if IgnoreCase then
        while (CharUpper(SourcePtr^) <> C) and (SourcePtr^ <> #0) do
        begin
          ResultPtr^ := SourcePtr^;
          Inc(ResultPtr);
          Inc(SourcePtr);
        end
      else
        while (SourcePtr^ <> C) and (SourcePtr^ <> #0) do
        begin
          ResultPtr^ := SourcePtr^;
          Inc(ResultPtr);
          Inc(SourcePtr);
        end;
      { did we find that first character or did we hit the end of the string? }
      if SourcePtr^ = #0 then
        Break
      else
      begin
        { continue comparing, +1 because first character was matched already }
        SourceMatchPtr := SourcePtr + 1;
        SearchMatchPtr := PChar(SearchStr) + 1;
        if IgnoreCase then
          while (CharUpper(SourceMatchPtr^) = SearchMatchPtr^) and (SearchMatchPtr^ <> #0) do
          begin
            Inc(SourceMatchPtr);
            Inc(SearchMatchPtr);
          end
        else
          while (SourceMatchPtr^ = SearchMatchPtr^) and (SearchMatchPtr^ <> #0) do
          begin
            Inc(SourceMatchPtr);
            Inc(SearchMatchPtr);
          end;
        { did we find a complete match? }
        if SearchMatchPtr^ = #0 then
        begin
          // keep track of result length
          Inc(ResultLength, ReplaceLength - SearchLength);
          if ReplaceLength > 0 then
          begin
            // increase buffer size if required
            if ResultLength > BufferLength then
            begin
              BufferLength := ResultLength * 2;
              ResultIndex := ResultPtr - PChar(ResultStr) + 1;
              SetLength(ResultStr, BufferLength);
              ResultPtr := @ResultStr[ResultIndex];
            end;
            { append replace to result and move past the search string in source }
            Move((@Replace[1])^, ResultPtr^, ReplaceLength * SizeOf(Char));
          end;
          Inc(SourcePtr, SearchLength);
          Inc(ResultPtr, ReplaceLength);
          { replace all instances or just one? }
          if not (rfReplaceAll in Flags) then
          begin
            { just one, copy until end of source and break out of loop }
            while SourcePtr^ <> #0 do
            begin
              ResultPtr^ := SourcePtr^;
              Inc(ResultPtr);
              Inc(SourcePtr);
            end;
            Break;
          end;
        end
        else
        begin
          { copy current character and start over with the next }
          ResultPtr^ := SourcePtr^;
          Inc(ResultPtr);
          Inc(SourcePtr);
        end;
      end;
    end;
    { set result length and copy result into S }
    SetLength(ResultStr, ResultLength);
    S := ResultStr;
  end;
end;

function StrReplaceChar(const S: string; const Source, Replace: Char): string;
var
  I: SizeInt;
begin
  Result := S;
  for I := 1 to Length(S) do
    if Result[I] = Source then
      Result[I] := Replace;
end;

function StrReplaceChars(const S: string; const Chars: TCharValidator; Replace: Char): string;
var
  I: SizeInt;
begin
  Result := S;
  for I := 1 to Length(S) do
    if Chars(Result[I]) then
      Result[I] := Replace;
end;

function StrReplaceChars(const S: string; const Chars: array of Char; Replace: Char): string;
var
  I: SizeInt;
begin
  Result := S;
  for I := 1 to Length(S) do
    if ArrayContainsChar(Chars, Result[I]) then
      Result[I] := Replace;
end;

function StrReplaceButChars(const S: string; const Chars: TCharValidator;
  Replace: Char): string;
var
  I: SizeInt;
begin
  Result := S;
  for I := 1 to Length(S) do
    if not Chars(Result[I]) then
      Result[I] := Replace;
end;

function StrReplaceButChars(const S: string; const Chars: array of Char; Replace: Char): string;
var
  I: SizeInt;
begin
  Result := S;
  for I := 1 to Length(S) do
    if not ArrayContainsChar(Chars, Result[I]) then
      Result[I] := Replace;
end;

function StrReverse(const S: string): string;
begin
  Result := S;
  StrReverseInplace(Result);
end;

procedure StrReverseInPlace(var S: string);
{ TODO -oahuser : Warning: This is dangerous for unicode surrogates }
var
  P1, P2: PChar;
  C: Char;
begin
  UniqueString(S);
  P1 := PChar(S);
  P2 := P1 + (Length(S) - 1);
  while P1 < P2 do
  begin
    C := P1^;
    P1^ := P2^;
    P2^ := C;
    Inc(P1);
    Dec(P2);
  end;
end;

function StrSingleQuote(const S: string): string;
begin
  Result := NativeSingleQuote + S + NativeSingleQuote;
end;

procedure StrSkipChars(var S: PChar; const Chars: TCharValidator);
begin
  while Chars(S^) do
    Inc(S);
end;

procedure StrSkipChars(var S: PChar; const Chars: array of Char);
begin
  while ArrayContainsChar(Chars, S^) do
    Inc(S);
end;

procedure StrSkipChars(const S: string; var Index: SizeInt; const Chars: TCharValidator);
begin
  while Chars(S[Index]) do
    Inc(Index);
end;

procedure StrSkipChars(const S: string; var Index: SizeInt; const Chars: array of Char);
begin
  while ArrayContainsChar(Chars, S[Index]) do
    Inc(Index);
end;

function StrSmartCase(const S: string; const Delimiters: array of Char): string;
var
  Source, Dest: PChar;
  Index, Len:   SizeInt;
begin
  Result := '';

  if S <> '' then
  begin
    Result := S;
    UniqueString(Result);

    Len := Length(S);
    Source := PChar(S);
    Dest := PChar(Result);
    Inc(Dest);

    for Index := 2 to Len do
    begin
      if ArrayContainsChar(Delimiters, Source^) and not ArrayContainsChar(Delimiters, Dest^) then
        Dest^ := CharUpper(Dest^);
      Inc(Dest);
      Inc(Source);
    end;
    Result[1] := CharUpper(Result[1]);
  end;
end;

function StrStringToEscaped(const S: string): string;
var
  I: SizeInt;
begin
  Result := '';
  for I := 1 to Length(S) do
  begin
    case S[I] of
      NativeBackspace:
        Result := Result + '\b';
      NativeBell:
        Result := Result + '\a';
      NativeCarriageReturn:
        Result := Result + '\r';
      NAtiveFormFeed:
        Result := Result + '\f';
      NativeLineFeed:
        Result := Result + '\n';
      NativeTab:
        Result := Result + '\t';
      NativeVerticalTab:
        Result := Result + '\v';
      NativeBackSlash:
        Result := Result + '\\';
      NativeDoubleQuote:
        Result := Result + '\"';
    else
      // Characters < ' ' are escaped with hex sequence
      if S[I] < #32 then
        Result := Result + Format('\x%.2x', [SizeInt(S[I])])
      else
        Result := Result + S[I];
    end;
  end;
end;

function StrStripNonNumberChars(const S: string): string;
var
  I: SizeInt;
  C: Char;
begin
  Result := '';
  for I := 1 to Length(S) do
  begin
    C := S[I];
    if CharIsNumberChar(C) then
      Result := Result + C;
  end;
end;

function StrToHex(const Source: string): string;
var
  Index: SizeInt;
  C, L, N: SizeInt;
  BL, BH: Byte;
  S:     string;
begin
  Result := '';
  if Source <> '' then
  begin
    S := Source;
    L := Length(S);
    if Odd(L) then
    begin
      S := '0' + S;
      Inc(L);
    end;
    Index := 1;
    SetLength(Result, L div 2);
    C := 1;
    N := 1;
    while C <= L do
    begin
      BH := CharHex(S[Index]);
      Inc(Index);
      BL := CharHex(S[Index]);
      Inc(Index);
      Inc(C, 2);
      if (BH = $FF) or (BL = $FF) then
      begin
        Result := '';
        Exit;
      end;
      Result[N] := Char((BH shl 4) or BL);
      Inc(N);
    end;
  end;
end;

function StrTrimCharLeft(const S: string; C: Char): string;
var
  I, L: SizeInt;
begin
  I := 1;
  L := Length(S);
  while (I <= L) and (S[I] = C) do
    Inc(I);
  Result := Copy(S, I, L - I + 1);
end;

function StrTrimCharsLeft(const S: string; const Chars: TCharValidator): string;
var
  I, L: SizeInt;
begin
  I := 1;
  L := Length(S);
  while (I <= L) and Chars(S[I]) do
    Inc(I);
  Result := Copy(S, I, L - I + 1);
end;

function StrTrimCharsLeft(const S: string; const Chars: array of Char): string;
var
  I, L: SizeInt;
begin
  I := 1;
  L := Length(S);
  while (I <= L) and ArrayContainsChar(Chars, S[I]) do
    Inc(I);
  Result := Copy(S, I, L - I + 1);
end;

function StrTrimCharRight(const S: string; C: Char): string;
var
  I: SizeInt;
begin
  I := Length(S);
  while (I >= 1) and (S[I] = C) do
    Dec(I);
  Result := Copy(S, 1, I);
end;

function StrTrimCharsRight(const S: string; const Chars: TCharValidator): string;
var
  I: SizeInt;
begin
  I := Length(S);
  while (I >= 1) and Chars(S[I]) do
    Dec(I);
  Result := Copy(S, 1, I);
end;

function StrTrimCharsRight(const S: string; const Chars: array of Char): string;
var
  I: SizeInt;
begin
  I := Length(S);
  while (I >= 1) and ArrayContainsChar(Chars, S[I]) do
    Dec(I);
  Result := Copy(S, 1, I);
end;

function StrTrimQuotes(const S: string): string;
var
  First, Last: Char;
  L: SizeInt;
begin
  L := Length(S);
  if L > 1 then
  begin
    First := S[1];
    Last := S[L];
    if (First = Last) and ((First = NativeSingleQuote) or (First = NativeDoubleQuote)) then
      Result := Copy(S, 2, L - 2)
    else
      Result := S;
  end
  else
    Result := S;
end;


//=== String Extraction ======================================================

function StrAfter(const SubStr, S: string): string;
var
  P: SizeInt;
begin
  P := StrFind(SubStr, S, 1); // StrFind is case-insensitive pos
  if P <= 0 then
    Result := ''           // substr not found -> nothing after it
  else
    Result := StrRestOf(S, P + Length(SubStr));
end;

function StrBefore(const SubStr, S: string): string;
var
  P: SizeInt;
begin
  P := StrFind(SubStr, S, 1);
  if P <= 0 then
    Result := S
  else
    Result := StrLeft(S, P - 1);
end;

function StrSplit(const SubStr, S: string;var Left, Right : string): boolean;
var
  P: SizeInt;
begin
  P := StrFind(SubStr, S, 1);
  Result:= p > 0;
  if Result then
  begin
    Left := StrLeft(S, P - 1);
    Right := StrRestOf(S, P + Length(SubStr));
  end
  else
  begin
    Left := '';
    Right := '';
  end;
end;

function StrBetween(const S: string; const Start, Stop: Char): string;
var
  PosStart, PosEnd: SizeInt;
  L: SizeInt;
begin
  PosStart := Pos(Start, S);
  PosEnd := StrSearch(Stop, S, PosStart + 1);  // PosEnd has to be after PosStart.

  if (PosStart > 0) and (PosEnd > PosStart) then
  begin
    L := PosEnd - PosStart;
    Result := Copy(S, PosStart + 1, L - 1);
  end
  else
    Result := '';
end;

function StrChopRight(const S: string; N: SizeInt): string;
begin
  Result := Copy(S, 1, Length(S) - N);
end;

function StrLeft(const S: string; Count: SizeInt): string;
begin
  Result := Copy(S, 1, Count);
end;

function StrMid(const S: string; Start, Count: SizeInt): string;
begin
  Result := Copy(S, Start, Count);
end;

function StrRestOf(const S: string; N: SizeInt): string;
begin
  Result := Copy(S, N, (Length(S) - N + 1));
end;

function StrRight(const S: string; Count: SizeInt): string;
begin
  Result := Copy(S, Length(S) - Count + 1, Count);
end;


//=== Miscellaneous ==========================================================

function FileToString(const FileName: string): {$IFDEF COMPILER12_UP}RawByteString{$ELSE}AnsiString{$ENDIF};
var
  fs: TFileStream;
  Len: SizeInt;
begin
  fs := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    Len := fs.Size;
    SetLength(Result, Len);
    if Len > 0 then
      fs.ReadBuffer(Result[1], Len);
  finally
    fs.Free;
  end;
end;

procedure StringToFile(const FileName: string; const Contents: {$IFDEF COMPILER12_UP}RawByteString{$ELSE}AnsiString{$ENDIF};
  Append: Boolean);
var
  FS: TFileStream;
  Len: SizeInt;
begin
  if Append and FileExists(filename) then
    FS := TFileStream.Create(FileName, fmOpenReadWrite or fmShareDenyWrite)
  else
    FS := TFileStream.Create(FileName, fmCreate);
  try
    if Append then
      FS.Seek(0, soEnd);  // faster than .Position := .Size
    Len := Length(Contents);
    if Len > 0 then
      FS.WriteBuffer(Contents[1], Len);
  finally
    FS.Free;
  end;
end;

function StrToken(var S: string; Separator: Char): string;
var
  I: SizeInt;
begin
  I := Pos(Separator, S);
  if I <> 0 then
  begin
    Result := Copy(S, 1, I - 1);
    Delete(S, 1, I);
  end
  else
  begin
    Result := S;
    S := '';
  end;
end;

procedure StrTokens(const S: string; const List: TStrings);
var
  Start: PChar;
  Token: string;
  Done:  Boolean;
begin
  Assert(List <> nil);
  if List = nil then
    Exit;

  List.BeginUpdate;
  try
    List.Clear;
    Start := Pointer(S);
    repeat
      Done := tisStrings.StrWord(Start, Token);
      if Token <> '' then
        List.Add(Token);
    until Done;
  finally
    List.EndUpdate;
  end;
end;

function StrWord(const S: string; var Index: SizeInt; out Word: string): Boolean;
var
  Start: SizeInt;
  C: Char;
begin
  Word := '';
  if (S = '') then
  begin
    Result := True;
    Exit;
  end;
  Start := Index;
  Result := False;
  while True do
  begin
    C := S[Index];
    case C of
      #0:
        begin
          if Start <> 0 then
            Word := Copy(S, Start, Index - Start);
          Result := True;
          Exit;
        end;
      NativeSpace, NativeLineFeed, NativeCarriageReturn:
        begin
          if Start <> 0 then
          begin
            Word := Copy(S, Start, Index - Start);
            Exit;
          end
          else
          begin
            while CharIsWhiteSpace(C) do
            begin
              Inc(Index);
              C := S[Index];
            end;
          end;
        end;
    else
      if Start = 0 then
        Start := Index;
      Inc(Index);
    end;
  end;
end;

function StrWord(var S: PChar; out Word: string): Boolean;
var
  Start: PChar;
begin
  Word := '';
  if S = nil then
  begin
    Result := True;
    Exit;
  end;
  Start := nil;
  Result := False;
  while True do
  begin
    case S^ of
      #0:
      begin
        if Start <> nil then
          SetString(Word, Start, S - Start);
        Result := True;
        Exit;
      end;
      NativeSpace, NativeLineFeed, NativeCarriageReturn:
      begin
        if Start <> nil then
        begin
          SetString(Word, Start, S - Start);
          Exit;
        end
        else
          while CharIsWhiteSpace(S^) do
            Inc(S);
      end;
    else
      if Start = nil then
        Start := S;
      Inc(S);
    end;
  end;
end;

function StrIdent(const S: string; var Index: SizeInt; out Ident: string): Boolean;
var
  Start: SizeInt;
  C: Char;
begin
  Ident := '';
  if (S = '') then
  begin
    Result := True;
    Exit;
  end;
  Start := Index;
  Result := False;
  while True do
  begin
    C := S[Index];
    if CharIsValidIdentifierLetter(C) then
    begin
      if Start = 0 then
        Start := Index;
    end
    else
    if C = #0 then
    begin
      if Start <> 0 then
        Ident := Copy(S, Start, Index - Start);
      Result := True;
      Exit;
    end
    else
    begin
      if Start <> 0 then
      begin
        Ident := Copy(S, Start, Index - Start);
        Exit;
      end;
    end;
    Inc(Index);
  end;
end;

function StrIdent(var S: PChar; out Ident: string): Boolean;
var
  Start: PChar;
  C: Char;
begin
  Ident := '';
  if S = nil then
  begin
    Result := True;
    Exit;
  end;
  Start := nil;
  Result := False;
  while True do
  begin
    C := S^;
    if CharIsValidIdentifierLetter(C) then
    begin
      if Start = nil then
        Start := S;
    end
    else
    if C = #0 then
    begin
      if Start <> nil then
        SetString(Ident, Start, S - Start);
      Result := True;
      Exit;
    end
    else
    begin
      if Start <> nil then
      begin
        SetString(Ident, Start, S - Start);
        Exit;
      end
    end;
    Inc(S);
  end;
end;

procedure StrTokenToStrings(S: string; Separator: Char; const List: TStrings);
var
  Token: string;
begin
  Assert(List <> nil);

  if List = nil then
    Exit;

  List.BeginUpdate;
  try
    List.Clear;
    while S <> '' do
    begin
      Token := StrToken(S, Separator);
      List.Add(Token);
    end;
  finally
    List.EndUpdate;
  end;
end;

function ArrayOf(List: TStrings): TDynStringArray;
var
  I: SizeInt;
begin
  if List <> nil then
  begin
    SetLength(Result, List.Count);
    for I := 0 to List.Count - 1 do
      Result[I] := List[I];
  end
  else
    Result := nil;
end;



//=== Character Search and Replace ===========================================

function CharLastPos(const S: string; const C: Char; const Index: SizeInt): SizeInt;
begin
  if (Index > 0) and (Index <= Length(S)) then
  begin
    for Result := Length(S) downto Index do
      if S[Result] = C then
        Exit;
  end;
  Result := 0;
end;

function CharPos(const S: string; const C: Char; const Index: SizeInt): SizeInt;
begin
  if (Index > 0) and (Index <= Length(S)) then
  begin
    for Result := Index to Length(S) do
      if S[Result] = C then
        Exit;
  end;
  Result := 0;
end;

function CharIPos(const S: string; C: Char; const Index: SizeInt): SizeInt;
begin
  if (Index > 0) and (Index <= Length(S)) then
  begin
    C := CharUpper(C);
    for Result := Index to Length(S) do
      if CharUpper(S[Result]) = C then
        Exit;
  end;
  Result := 0;
end;

function CharReplace(var S: string; const Search, Replace: Char): SizeInt;
var
  P: PChar;
  Index, Len: SizeInt;
begin
  Result := 0;
  if Search <> Replace then
  begin
    UniqueString(S);
    P := PChar(S);
    Len := Length(S);
    for Index := 0 to Len - 1 do
    begin
      if P^ = Search then
      begin
        P^ := Replace;
        Inc(Result);
      end;
      Inc(P);
    end;
  end;
end;

//=== Character (do we have it ;) ============================================

function CharEqualNoCase(const C1, C2: Char): Boolean;
begin
  //if they are not equal chars, may be same letter different case
  Result := (C1 = C2) or
    (CharIsAlpha(C1) and CharIsAlpha(C2) and (CharLower(C1) = CharLower(C2)));
end;


function CharIsAlpha(const C: Char): Boolean;
begin
  Result := TCharacter.IsLetter(C);
end;

function CharIsAlphaNum(const C: Char): Boolean;
begin
  {$IFDEF UNICODE_RTL_DATABASE}
  Result := TCharacter.IsLetterOrDigit(C);
  {$ELSE ~UNICODE_RTL_DATABASE}
  Result := ((StrCharTypes[C] and C1_ALPHA) <> 0) or ((StrCharTypes[C] and C1_DIGIT) <> 0);
  {$ENDIF ~UNICODE_RTL_DATABASE}
end;

function CharIsBlank(const C: Char): Boolean;
begin
  {$IFDEF UNICODE_RTL_DATABASE}
  //http://blogs.msdn.com/b/michkap/archive/2007/06/11/3230072.aspx
  Result := (C = ' ') or (C = #$0009) or (C = #$00A0) or (C = #$3000);
  {$ELSE ~UNICODE_RTL_DATABASE}
  Result := ((StrCharTypes[C] and C1_BLANK) <> 0);
  {$ENDIF ~UNICODE_RTL_DATABASE}
end;

function CharIsControl(const C: Char): Boolean;
begin
  {$IFDEF UNICODE_RTL_DATABASE}
  Result := TCharacter.IsControl(C);
  {$ELSE ~UNICODE_RTL_DATABASE}
  Result := (StrCharTypes[C] and C1_CNTRL) <> 0;
  {$ENDIF ~UNICODE_RTL_DATABASE}
end;

function CharIsDelete(const C: Char): Boolean;
begin
  Result := (C = #8);
end;

function CharIsDigit(const C: Char): Boolean;
begin
  {$IFDEF UNICODE_RTL_DATABASE}
  Result := TCharacter.IsDigit(C);
  {$ELSE ~UNICODE_RTL_DATABASE}
  Result := (StrCharTypes[C] and C1_DIGIT) <> 0;
  {$ENDIF ~UNICODE_RTL_DATABASE}
end;

function CharIsFracDigit(const C: Char): Boolean;
begin
  Result := (C = '.') or CharIsDigit(C);
end;

function CharIsHexDigit(const C: Char): Boolean;
begin
  case C of
    'A'..'F',
    'a'..'f':
      Result := True;
  else
    Result := CharIsDigit(C);
  end;
end;

function CharIsLower(const C: Char): Boolean;
begin
  {$IFDEF UNICODE_RTL_DATABASE}
  Result := TCharacter.IsLower(C);
  {$ELSE ~UNICODE_RTL_DATABASE}
  Result := (StrCharTypes[C] and C1_LOWER) <> 0;
  {$ENDIF ~UNICODE_RTL_DATABASE}
end;

function CharIsNumberChar(const C: Char): Boolean;
begin
  Result := CharIsDigit(C) or (C = '+') or (C = '-') or (C = DecimalSeparator);
end;

function CharIsNumber(const C: Char): Boolean;
begin
  Result := CharIsDigit(C) or (C = DecimalSeparator);
end;

function CharIsPrintable(const C: Char): Boolean;
begin
  Result := not CharIsControl(C);
end;

function CharIsPunctuation(const C: Char): Boolean;
begin
  {$IFDEF UNICODE_RTL_DATABASE}
  Result := TCharacter.IsPunctuation(C);
  {$ELSE ~UNICODE_RTL_DATABASE}
  Result := ((StrCharTypes[C] and C1_PUNCT) <> 0);
  {$ENDIF ~UNICODE_RTL_DATABASE}
end;

function CharIsReturn(const C: Char): Boolean;
begin
  Result := (C = NativeLineFeed) or (C = NativeCarriageReturn);
end;

function CharIsSpace(const C: Char): Boolean;
begin
  {$IFDEF UNICODE_RTL_DATABASE}
  Result := TCharacter.IsWhiteSpace(C);
  {$ELSE ~UNICODE_RTL_DATABASE}
  Result := (StrCharTypes[C] and C1_SPACE) <> 0;
  {$ENDIF ~UNICODE_RTL_DATABASE}
end;

function CharIsUpper(const C: Char): Boolean;
begin
  {$IFDEF UNICODE_RTL_DATABASE}
  Result := TCharacter.IsUpper(C);
  {$ELSE ~UNICODE_RTL_DATABASE}
  Result := (StrCharTypes[C] and C1_UPPER) <> 0;
  {$ENDIF ~UNICODE_RTL_DATABASE}
end;

function CharIsValidIdentifierLetter(const C: Char): Boolean;
begin
  case C of
    {$IFDEF SUPPORTS_UNICODE}
    // from XML specifications
    #$00C0..#$00D6, #$00D8..#$00F6, #$00F8..#$02FF, #$0370..#$037D,
    #$037F..#$1FFF, #$200C..#$200D, #$2070..#$218F, #$2C00..#$2FEF,
    #$3001..#$D7FF, #$F900..#$FDCF, #$FDF0..#$FFFD, // #$10000..#$EFFFF, howto match surrogate pairs?
    #$00B7, #$0300..#$036F, #$203F..#$2040,
    {$ENDIF SUPPORTS_UNICODE}
    '0'..'9', 'A'..'Z', 'a'..'z', '_':
      Result := True;
  else
    Result := False;
  end;
end;

function CharIsWhiteSpace(const C: Char): Boolean;
begin
  case C of
    NativeTab,
    NativeLineFeed,
    NativeVerticalTab,
    NativeFormFeed,
    NativeCarriageReturn,
    NativeSpace:
      Result := True;
  else
    Result := False;
  end;
end;

function CharIsWildcard(const C: Char): Boolean;
begin
  case C of
    '*', '?':
      Result := True;
  else
    Result := False;
  end;
end;



//=== Character Transformation Routines ======================================

function CharHex(const C: Char): Byte;
begin
  case C of
    '0'..'9':
      Result := Ord(C) - Ord('0');
    'a'..'f':
      Result := Ord(C) - Ord('a') + 10;
    'A'..'F':
      Result := Ord(C) - Ord('A') + 10;
  else
    Result := $FF;
  end;
end;

function CharLower(const C: Char): Char;
begin
  {$IFDEF UNICODE_RTL_DATABASE}
  Result := TCharacter.ToLower(C);
  {$ELSE ~UNICODE_RTL_DATABASE}
  Result := StrCaseMap[Ord(C) + StrLoOffset];
  {$ENDIF ~UNICODE_RTL_DATABASE}
end;

function CharToggleCase(const C: Char): Char;
begin
  {$IFDEF UNICODE_RTL_DATABASE}
  if CharIsLower(C) then
    Result := CharUpper(C)
  else if CharIsUpper(C) then
    Result := CharLower(C)
  else
    Result := C;
  {$ELSE ~UNICODE_RTL_DATABASE}
  Result := StrCaseMap[Ord(C) + StrReOffset];
  {$ENDIF ~UNICODE_RTL_DATABASE}
end;

function CharUpper(const C: Char): Char;
begin
  {$IFDEF UNICODE_RTL_DATABASE}
  Result := TCharacter.ToUpper(C);
  {$ELSE ~UNICODE_RTL_DATABASE}
  Result := StrCaseMap[Ord(C) + StrUpOffset];
  {$ENDIF ~UNICODE_RTL_DATABASE}
end;



end.

