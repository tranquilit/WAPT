pushd %~dp0
mklink %CD%\python.exe %CD%\Scripts\python.exe
SET VIRTUAL_ENV=%CD%
SET PYTHONHOME=%VIRTUAL_ENV%
start "Wapt Pycripter" /D "%CD%" "C:\Program Files (x86)\PyScripter\PyScripter.exe" -N --python27 --PYTHONDLLPATH "%cd%"  --project "%cd%\waptservice\waptservice.psproj"' %*
popd
