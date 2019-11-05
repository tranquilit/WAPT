@echo off
REM Run waptservice python script in wapt virtualenv for debugging purpose
net stop wapttasks
pushd %~dp0
SET VIRTUAL_ENV=%CD%
SET PYTHONHOME=%VIRTUAL_ENV%
"%PYTHONHOME%\waptpython.exe" "%PYTHONHOME%\waptserver\wapthuey.py" waptenterprise.waptserver.wsus_tasks.huey -w 2 -k thread %*
popd
