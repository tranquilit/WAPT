@echo off
REM Run wapt-scanpackages python script in wapt virtualenv
pushd %~dp0
SET VIRTUAL_ENV=%CD%
SET PYTHONHOME=%VIRTUAL_ENV%
"%PYTHONHOME%\waptpython.ex"e "%PYTHONHOME%\wapt-scanpackages.py" %*
popd
