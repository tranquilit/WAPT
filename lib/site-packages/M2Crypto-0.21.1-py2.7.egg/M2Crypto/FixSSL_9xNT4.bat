echo off
cls

echo This application modifies the OpenSSL binaries so that they work under
echo Win9x/Me/NT4.  The modifications are general-purpose and don't violate
echo default build rules.  Use of this tool is at your own risk!
echo.
echo ("Your own risk" being technical, legal, etc. issues)
echo.
echo.
echo Don't forget to donate to OpenSSL!
echo.
echo.
echo.
pause
cls

if exist osslkrnl.dll goto AlreadyFixed

if not exist libeay32.dll goto NotBinInstalled
if not exist ssleay32.dll goto NotBinInstalled

if not exist %windir%\PEProxy.exe goto MissingDependency

if exist %windir%\system32\vc90hook.dll goto DetectedNT
if not exist %windir%\system\vc90hook.dll goto MissingDependency

rem Win9x/Me only.
copy %windir%\system\vc90hook.dll .
copy %windir%\system\unicows.dll .

goto RunMain


:DetectedNT
copy %windir%\system32\vc90hook.dll .
copy %windir%\system32\unicows.dll .


:RunMain
PEProxy kernel32.dll osslkrnl.dll vc90hook.dll*unicows.dll libeay32.dll ssleay32.dll openssl.exe
copy ssleay32.dll libssl32.dll
erase vc90hook.dll
erase unicows.dll
erase *.bak.*
copy *.dll ..\.

goto end


:AlreadyFixed
cls
echo Already fixed.
echo.
echo It appears that OpenSSL has already been modified for use for your OS.
pause
goto end


:NotBinInstalled
cls
echo A dependency of this program is missing.
echo.
echo Did you install OpenSSL with the /bin option?
pause
goto end


:MissingDependency
cls
echo A dependency of this program is missing.
echo.
echo Did you install the RunMagic version of the VC++ 2008 Redistributables
echo globally using the InstallGlobal application included with RunMagic?
pause
goto end

:end
cls
