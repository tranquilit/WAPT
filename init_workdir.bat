
virtualenv .
xcopy /I /E /F /Y c:\python27\libs libs
xcopy /I /E /F /Y c:\python27\DLLs DLLs
xcopy /I /E /F /Y /EXCLUDE:libexcludes.txt c:\python27\lib lib

virtualenv --relocatable .
Scripts\activate.bat
pip install --upgrade pip setuptools wheel virtualenv
rem wget "https://downloads.sourceforge.net/project/pywin32/pywin32/Build%20220/pywin32-220.win32-py2.7.exe?r=&ts=1486553375&use_mirror=kent" --no-check-certificate
Scripts\easy_install.exe c:\binaries\pywin32-220.win32-py2.7.exe
pip install -r requirements.txt

copy /Y lib\site-packages\pywin32-220-py2.7-win32.egg\py*.dll .
copy /Y c:\windows\SysWOW64\python27.dll .

copy /Y lib\site-packages\M2Crypto\*.dll .
copy /Y utils\openssl.exe lib\site-packages\M2Crypto\
copy /Y Scripts\python.exe waptpython.exe
copy /Y Scripts\pythonw.exe waptpythonw.exe
