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
xcopy /I /E /F /Y c:\python27\libs %~dp0\libs
xcopy /I /E /F /Y c:\python27\DLLs %~dp0\DLLs
xcopy /I /E /F /Y /EXCLUDE:%~dp0\libexcludes.txt c:\python27\lib %~dp0\lib

%~dp0\Scripts\python  -m pip install -U pip setuptools wheel virtualenv six requests==2.19.1 psutil==3.4.2

REM get  pywin32-220.win32Sc            -py2.7.exe from internet
python -c "from urllib import urlretrieve; from subprocess import check_output; pywin32=urlretrieve('https://github.com/mhammond/pywin32/releases/download/b223/pywin32-223.win32-py2.7.exe');print(pywin32[0]); print(check_output(r'%~dp0\Scripts\easy_install.exe %%s' %% (pywin32[0]),shell=True));"
%~dp0\Scripts\pip.exe install -r %~dp0\requirements.txt -r %~dp0\requirements-windows.txt

rem copy /Y %0\..\lib\site-packages\pywin32-220-py2.7-win32.egg\py*.dll %0\..\
copy /Y c:\windows\SysWOW64\python27.dll %~dp0\
rem copy /Y c:\windows\SysWOW64\pythoncom27.dll %0\..\
rem /Y c:\windows\SysWOW64\pythoncomloader27.dll %0\..\
rem /Y c:\windows\SysWOW64\pywintypes27.dll %0\..\

copy /Y %~dp0\Scripts\python.exe %~dp0\waptpython.exe
copy /Y %~dp0\Scripts\pythonw.exe %~dp0\waptpythonw.exe

REM Patch memory leak
copy /Y %~dp0\utils\patch-socketio-client-2\__init__.py  %~dp0\lib\site-packages\socketIO_client\
copy /Y %~dp0\utils\patch-socketio-client-2\transports.py  %~dp0\lib\site-packages\socketIO_client\

REM Patch x509 certificate signature checking
copy /Y %~dp0\utils\patch-cryptography\__init__.py  %~dp0\lib\site-packages\cryptography\x509\
copy /Y %~dp0\utils\patch-cryptography\verification.py  %~dp0\lib\site-packages\cryptography\x509\

REM get iscc nginx and pgsql binaries
%~dp0\waptpython.exe %~dp0\update_binaries.py
