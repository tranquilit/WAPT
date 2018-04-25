pushd %~dp0
if not exist "%CD%\python.exe" copy "%CD%\Scripts\python.exe" "%CD%\python.exe"
set VIRTUAL_ENV=%CD%
SET PYTHONHOME=%VIRTUAL_ENV%
start "PyScripter" /D "%CD%" "%ProgramFiles(x86)%\PyScripter\PyScripter.exe" -N --python27 --PYTHONDLLPATH "%cd%" %*
popd
