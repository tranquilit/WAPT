net stop waptserver
sc delete waptserver
net stop waptmongodb /yes
sc delete waptmongodb
net stop waptapache /yes
sc delete waptapache
