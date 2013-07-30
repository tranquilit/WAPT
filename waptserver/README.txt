WAPTServer serves wapt packages and desktops configuration on the network
It is made of two services :
* WAPTServer, a python based service, which depends on waptmongodb
* WAPTmongodb service, a mongodb database that store clients machines inventory

Note : 
* MongoDB is not in the lastest version, due to a bug on the service start/stop mechanism in mogodb > 2.1


