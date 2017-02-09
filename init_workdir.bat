
git clean -xfd

virtualenv . --distribute
xcopy /I /E /F /Y c:\python27\libs libs
xcopy /I /E /F /Y c:\python27\DLLs DLLs
xcopy /I /E /F /Y /EXCLUDE:libexcludes.txt c:\python27\lib lib

virtualenv --relocatable .
Scripts\pip install --upgrade pip setuptools wheel virtualenv
Scripts\easy_install.exe c:\binaries\pywin32-220.win32-py2.7.exe
Scripts\pip install -r requirements.txt

copy /Y lib\site-packages\pywin32-220-py2.7-win32.egg\py*.dll .
copy /Y c:\windows\SysWOW64\python27.dll .

copy /Y lib\site-packages\M2Crypto\*.dll .
copy /Y utils\openssl.exe lib\site-packages\M2Crypto\
copy /Y Scripts\python.exe waptpython.exe
copy /Y Scripts\pythonw.exe waptpythonw.exe