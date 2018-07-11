REM build_win
call init_workdir.bat
waptpython build_exe.py community
"c:\Program Files\PuTTY\pscp.exe" *.exe waptsetup\*.exe tisadmin@buildbot:/home/tisadmin/public_html/wapt-1.5.1.25/community/

waptpython build_exe.py enterprise
"c:\Program Files\PuTTY\pscp.exe" *.exe waptsetup\*.exe tisadmin@buildbot:/home/tisadmin/public_html/wapt-1.5.1.25/enterprise/
