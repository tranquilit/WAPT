unit uWAPTPollThreads;

{$mode objfpc}{$H+}

{$if defined(windows)}
{$include uWAPTPollThreadsWindows.inc}
{$elseif defined(unix)}
{$include uWAPTPollThreadsUnix.inc}
{$else}
raise ENotImplemented.Create('waptcommon: OS not supported');
{$endif}
