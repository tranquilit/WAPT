REM  ##########################################"
REM  WAPT dev enviroment initialisation helper script
REM  this script does the provisioning of the wapt
REM  dev tree with dependencies and dll
REM  ##########################################"

set PYTHON_PATH=c:\python27
REM uncomment and modify the following lines if you need proxy for internet access
REM set http_proxy=http://srvproxy:8080
REM set https_proxy=http://srvproxy:8080

git -C %~dp0 clean -xfd
%PYTHON_PATH%\python.exe -m pip install -U pip setuptools
%PYTHON_PATH%\Scripts\pip.exe install virtualenv
%PYTHON_PATH%\Scripts\virtualenv.exe  --no-site-packages --always-copy %~dp0
xcopy /I /E /F /Y %PYTHON_PATH%\libs %~dp0\libs
xcopy /I /E /F /Y %PYTHON_PATH%\DLLs %~dp0\DLLs
xcopy /I /E /F /Y /EXCLUDE:%~dp0\libexcludes.txt %PYTHON_PATH%\lib %~dp0\lib

%~dp0\Scripts\python -m pip install -U pip setuptools wheel
%~dp0\Scripts\pip.exe install -r %~dp0\requirements.txt -r %~dp0\requirements-windows.txt

%PYTHON_PATH%\python.exe %~dp0\pywininstall.py
%~dp0\Scripts\easy_install.exe %~dp0\..\binaries_cache\pywin_install.exe
For /D %%A In ("%~dp0\lib\site-packages\pywin32_system32") Do @Copy "%%A\py*27.dll" "%~dp0"
For /D %%A In ("%~dp0\lib\site-packages\pywin32_system32") Do @Copy "%%A\py*27.dll" "%~dp0\lib\site-packages\win32"
For /D %%A In ("%~dp0\lib\site-packages\pywin32_system32") Do @Copy "%%A\py*27.dll" "%~dp0\Scripts"

copy /Y c:\windows\SysWOW64\python27.dll %~dp0\

copy /Y %~dp0\Scripts\python.exe %~dp0\waptpython.exe
copy /Y %~dp0\Scripts\pythonw.exe %~dp0\waptpythonw.exe

REM Patch memory leak
copy /Y %~dp0\utils\patch-socketio-client-2\__init__.py  %~dp0\lib\site-packages\socketIO_client\
copy /Y %~dp0\utils\patch-socketio-client-2\transports.py  %~dp0\lib\site-packages\socketIO_client\

REM Patch x509 certificate signature checking
copy /Y %~dp0\utils\patch-cryptography\__init__.py  %~dp0\lib\site-packages\cryptography\x509\
copy /Y %~dp0\utils\patch-cryptography\verification.py  %~dp0\lib\site-packages\cryptography\x509\

REM create full_version file
%~dp0\waptpython.exe %~dp0\create_version_full.py

REM get iscc nginx and pgsql binaries
%~dp0\waptpython.exe %~dp0\update_binaries.py