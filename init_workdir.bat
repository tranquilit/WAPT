REM  ##########################################"
REM  WAPT dev enviroment initialisation helper script
REM  this script does the provisioning of the wapt
REM  dev tree with dependencies and dll
REM  ##########################################"

set PYTHON_PATH=c:\python27

REM uncomment and modify the following lines if you need proxy for internet access
REM set http_proxy=http://srvproxy:8080
REM set https_proxy=http://srvproxy:8080

git -C %0\..\ clean -xfd 
%PYTHON_PATH%\python.exe -m pip install -U pip setuptools
%PYTHON_PATH%\Scripts\pip.exe install virtualenv
%PYTHON_PATH%\Scripts\virtualenv.exe  --no-site-packages --always-copy %0\..\ 
xcopy /I /E /F /Y c:\python27\libs %0\..\libs
xcopy /I /E /F /Y c:\python27\DLLs %0\..\DLLs
xcopy /I /E /F /Y /EXCLUDE:libexcludes.txt c:\python27\lib %0\..\lib

%0\..\Scripts\python  -m pip install -U pip setuptools wheel virtualenv six requests==2.19.1

REM get  pywin32-220.win32Sc            -py2.7.exe from internet
python -c "from waptutils import wget; from subprocess import check_output; pywin32=wget('https://github.com/mhammond/pywin32/releases/download/b223/pywin32-223.win32-py2.7.exe',resume=True,cache_dir='c:\\binaries',md5='366d181c39169d3b0c0e1d25f781d1d6'); print check_output('%0\..\Scripts\easy_install.exe ""%%s""' %% pywin32,shell=True)"
%0\..\Scripts\pip.exe install -r %0\..\requirements.txt -r %0\..\requirements-windows.txt

rem copy /Y %0\..\lib\site-packages\pywin32-220-py2.7-win32.egg\py*.dll %0\..\
copy /Y c:\windows\SysWOW64\python27.dll %0\..\
rem copy /Y c:\windows\SysWOW64\pythoncom27.dll %0\..\
rem /Y c:\windows\SysWOW64\pythoncomloader27.dll %0\..\
rem /Y c:\windows\SysWOW64\pywintypes27.dll %0\..\

copy /Y %0\..\Scripts\python.exe %0\..\waptpython.exe
copy /Y %0\..\Scripts\pythonw.exe %0\..\waptpythonw.exe

REM Patch memory leak
copy /Y %0\..\utils\patch-socketio-client-2\__init__.py  %0\..\lib\site-packages\socketIO_client\
copy /Y %0\..\utils\patch-socketio-client-2\transports.py  %0\..\lib\site-packages\socketIO_client\

REM Patch x509 certificate signature checking
copy /Y %0\..\utils\patch-cryptography\__init__.py  %0\..\lib\site-packages\cryptography\x509\
copy /Y %0\..\utils\patch-cryptography\verification.py  %0\..\lib\site-packages\cryptography\x509\

REM get iscc nginx and pgsql binaries
%0\..\waptpython.exe %0\..\update_binaries.py
