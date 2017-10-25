net stop waptserver
sc delete waptserver
net stop waptnginx /yes
sc delete waptnginx
net stop waptpostgresql /yes
sc delete waptpostgresql
