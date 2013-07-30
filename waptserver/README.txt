WAPTServer serves wapt packages and desktops configuration on the network
It is made of two services :
* WAPTServer, a python based service, which depends on waptmongodb
* WAPTmongodb service, a mongodb database that store clients machines inventory

Note : 
* MongoDB is not in the lastest version, due to a bug on the service start/stop mechanism in mogodb > 2.1


Configuration of WAPTServer on windows

C:\WAPT\waptserver\mongodb>mongod.exe --config c:\wapt\waptserver\mongodb\mongod.cfg --install
c:\python27\python waptserver_servicewrapper.py --startup=auto install 

net start waptmongodb
net start waptserver


Uninstall of waptserver services

net stop waptserver
sc delete waptserver
net stop waptmongodb
sc delete waptmongodb