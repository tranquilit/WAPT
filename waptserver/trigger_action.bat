@echo off
REM Run trigger_action.py python script in wapt virtualenv
pushd %~dp0
SET VIRTUAL_ENV=%CD%\..
SET PYTHONHOME=%VIRTUAL_ENV%
"%PYTHONHOME%\waptpython.exe" "%CD%\trigger_action.py" %*
popd
