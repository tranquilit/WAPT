REM  ##########################################"
REM  WAPT dev enviroment initialisation helper script
REM  this script does the provisioning of the wapt
REM  dev tree with dependencies and dll
REM  ##########################################"

set PYTHON_PATH=c:\python27

REM uncomment and modify the following lines if you need proxy for internet access
REM set http_proxy=http://proxy:3128
REM set https_proxy=http://proxy:3128

git clean -xfd
%PYTHON_PATH%\Scripts\pip.exe install -U pip distribute
%PYTHON_PATH%\Scripts\pip.exe install virtualenv
%PYTHON_PATH%\Scripts\virtualenv.exe .
xcopy /I /E /F /Y c:\python27\libs libs
xcopy /I /E /F /Y c:\python27\DLLs DLLs
xcopy /I /E /F /Y /EXCLUDE:libexcludes.txt c:\python27\lib lib

Scripts\pip.exe install --upgrade pip distribute wheel virtualenv six	

REM get  pywin32-220.win32-py2.7.exe from internet
waptpython -c "from waptutils import wget; from subprocess import check_output; pywin32=wget('https://github.com/mhammond/pywin32/releases/download/b223/pywin32-223.win32-py2.7.exe',resume=True,cache_dir='c:\\binaries',md5='366d181c39169d3b0c0e1d25f781d1d6'); print check_output('Scripts\easy_install.exe ""%%s""' %% pywin32,shell=True)"
Scripts\pip.exe install -r requirements.txt -r requirements-windows.txt

rem copy /Y lib\site-packages\pywin32-220-py2.7-win32.egg\py*.dll .
copy /Y c:\windows\SysWOW64\python27.dll .
rem copy /Y c:\windows\SysWOW64\pythoncom27.dll .
rem /Y c:\windows\SysWOW64\pythoncomloader27.dll .
rem /Y c:\windows\SysWOW64\pywintypes27.dll .

copy /Y Scripts\python.exe waptpython.exe
copy /Y Scripts\pythonw.exe waptpythonw.exe

REM Patch memory leak
copy /Y utils\patch-socketio-client-2\__init__.py  lib\site-packages\socketIO_client\
copy /Y utils\patch-socketio-client-2\transports.py  lib\site-packages\socketIO_client\

REM Patch x509 certificate signature checking
copy /Y utils\patch-cryptography\__init__.py  lib\site-packages\cryptography\x509\
copy /Y utils\patch-cryptography\verification.py  lib\site-packages\cryptography\x509\

REM get iscc nginx and pgsql binaries
waptpython.exe update_binaries.py
