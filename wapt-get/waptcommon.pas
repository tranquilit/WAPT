unit waptcommon;

{$mode objfpc}{$H+}

{$if defined(windows)}
{$include waptcommonwin.inc}
{$elseif defined(unix)}
{$include waptcommonunix.inc}
{$else}
raise ENotImplemented.Create('waptcommon: OS not supported');
{$endif}
