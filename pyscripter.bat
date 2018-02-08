pushd %~dp0
mklink %CD%\python.exe %CD%\Scripts\python.exe
set VIRTUAL_ENV=%CD%
SET PYTHONHOME=%VIRTUAL_ENV%
start "Pycripter" /D "%CD%" "C:\Program Files (x86)\PyScripter\PyScripter.exe" -N --python27 --PYTHONDLLPATH "%cd%" %1
popd
