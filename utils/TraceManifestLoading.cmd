@echo off
echo.
echo *************************************************
Echo * TraceManifestLoading.cmd from CSI-Windows.com *
Echo * http://CSI-Windows.com/courses                *
Echo *                                               *
Echo * Works for Vista, Win7, UAC, 2003, 2008        *
echo *************************************************
Rem CSI-Windows.com

for /f "tokens=3" %%V in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-18" /v ProfileImagePath ^| find "ProfileImagePath"') do set FOLDER=%%V
dir %FOLDER% 2>&1 | findstr /I /C:"Not Found"
If %ERRORLEVEL% == 0 GOTO :NOADMINABORT

Echo Starting sxstrace utility...
echo.
sxstrace Trace -logfile:%temp%\sxstrace.log

sxstrace Parse -logfile:%temp%\sxstrace.log -outfile:%temp%\sxstrace.txt

notepad %temp%\sxstrace.txt

GOTO :END
:NOADMINABORT
Echo You must be an elevated admin to run this script, 
Echo please elevate the script when starting it.
Echo.
Echo Aborting...
pause

:END