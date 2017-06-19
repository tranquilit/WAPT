REM  ##########################################"
REM  WAPT dev enviroment initialisation helper script
REM  this script does the provisioning of the wapt 
REM  dev tree with dependencies and dll
REM  ##########################################"

set PYTHON_PATH=c:\python27

git clean -xfd

%PYTHON_PATH%\Scripts\pip install virtualenv
%PYTHON_PATH%\Scripts\virtualenv . 
xcopy /I /E /F /Y c:\python27\libs libs
xcopy /I /E /F /Y c:\python27\DLLs DLLs
xcopy /I /E /F /Y /EXCLUDE:libexcludes.txt c:\python27\lib lib

Scripts\virtualenv --relocatable .
Scripts\pip install --upgrade pip setuptools wheel virtualenv six
REM  pywin32 is not available as binary wheel from standard pip download, it is 
REM  currently integrated into the git tree and installed directly from that file
Scripts\easy_install.exe utils\pywin32-220.win32-py2.7.exe
Scripts\pip install --require-hashes  -r requirements.txt

copy /Y lib\site-packages\pywin32-220-py2.7-win32.egg\py*.dll .
copy /Y c:\windows\SysWOW64\python27.dll .
copy /Y c:\windows\SysWOW64\pythoncom27.dll .
copy /Y c:\windows\SysWOW64\pythoncomloader27.dll .
copy /Y c:\windows\SysWOW64\pywintypes27.dll .
copy /Y .\lib\site-packages\M2Crypto\libeay32.dll . 
copy /Y .\lib\site-packages\M2Crypto\ssleay32.dll . 

copy /Y utils\openssl.exe lib\site-packages\M2Crypto\
copy /Y Scripts\python.exe waptpython.exe
copy /Y Scripts\pythonw.exe waptpythonw.exe