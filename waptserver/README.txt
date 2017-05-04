WAPTServer serves wapt packages and desktops configuration on the network.

It is composed of 3 services:

* WAPTServer, a python based service, which depends on PostgreSQL database server
* a PostgreSQL database that stores the inventory of client machines
* an Apache http server to serve Packages

Note: As of WAPT 1.4.3, on Windows, PostgreSQL must be installed manually.
