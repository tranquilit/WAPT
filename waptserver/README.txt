WAPTServer serves wapt packages and desktops configuration on the network.

It is composed of two services:

* WAPTServer, a python based service, which depends on mongodb
* a mongodb database that stores the inventory of client machines

Note: on Windows, MongoDB is packaged as the WAPTMongodb service.
It is not in the latest version, due to a bug in the service
start/stop mechanism in mogodb > 2.1
