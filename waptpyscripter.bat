pushd %~dp0
set VIRTUAL_ENV=%CD%
SET PYTHONHOME=%VIRTUAL_ENV%
start "PyScripter" /D "%CD%" "%ProgramFiles(x86)%\PyScripter\PyScripter.exe" -N --python27 --PYTHONDLLPATH "%cd%" %*
popd
