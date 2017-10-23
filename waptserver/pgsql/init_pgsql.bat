md data

REM we support that the server is not running (first install)
bin\initdb -E=UTF8 -D ./data/
bin\pg_ctl.exe -D ./data/ start
bin\psql.exe --command "create database wapt;" template1 
bin\psql.exe --command="create extension hstore;" wapt
..\..\waptpython.exe ..\waptserver_model.py init_db
bin\pg_ctl.exe -D ./data/ stop
