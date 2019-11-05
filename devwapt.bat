@echo off
pushd %~dp0
SET VIRTUAL_ENV=%CD%
SET PYTHONHOME=%VIRTUAL_ENV%
start "Wapt Pycripter" /D "%CD%" "C:\Program Files (x86)\PyScripter\PyScripter.exe" -N --python27 --PYTHONDLLPATH "%cd%"  --project "%cd%\wapt.psproj"'
popd
