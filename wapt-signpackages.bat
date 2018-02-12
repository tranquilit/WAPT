@echo off
REM Run wapt-signpackages python script in wapt virtualenv
pushd %~dp0
SET VIRTUAL_ENV=%CD%
SET PYTHONHOME=%VIRTUAL_ENV%
%PYTHONHOME%\waptpython.exe %PYTHONHOME%\wapt-signpackages.py %*
popd
