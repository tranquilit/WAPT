@echo off
REM Run waptservice python script in wapt virtualenv for debugging purpose
net stop waptservice
pushd %~dp0
SET VIRTUAL_ENV=%CD%
SET PYTHONHOME=%VIRTUAL_ENV%
"%PYTHONHOME%\waptpython.exe" "%PYTHONHOME%\waptservice\service.py" %*
popd
