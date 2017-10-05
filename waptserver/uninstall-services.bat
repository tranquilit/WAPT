net stop waptserver
sc delete waptserver
net stop nginx /yes
sc delete nginx
net stop pgsql /yes
sc delete pgsql
