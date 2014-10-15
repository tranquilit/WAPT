WAPT
====

WAPT est une solution qui automatise les installations, les désinstallations et
les mises à jour de l'ensemble des logiciels sur un parc informatique Windows.
Le déploiement de logiciels (Firefox, MS Office,...) à partir d'une console de
gestion centrale est maintenant possible. WAPT s'inspire fortement du
gestionnaire de paquets du système GNU/Linux Debian apt, d'où son nom.

Plus d'informations sur: http://dev.tranquil.it/index.php/WAPT

Licensing
=========

Copyright: Tranquil It Systems http://www.tranquil-it-systems.fr/
License: GPL v3.0

Le dépôt contient des sources (sous le répertoire /lib/)  provenant d'autres
projets et potentiellement soumis à d'autres licenses.


Composants de WAPT
==================

Environnement Python
--------------------

* Python 2.7.6
* Python 2.7 setuptools-0.6c11 : https://pypi.python.org/packages/2.7/s/setuptools/setuptools-0.6c11.win32-py2.7.exe
* Python 2.7 M2Crypto-0.21.1 : http://chandlerproject.org/pub/Projects/MeTooCrypto/M2Crypto-0.21.1.win32-py2.7.msi
* Python 2.7 pyOpenSSL-0.13 : http://www.egenix.com/products/python/pyOpenSSL/
* Python 2.7 pycrypto-2.6 : http://www.voidspace.org.uk/downloads/pycrypto26/pycrypto-2.6.win32-py2.7.exe
* Python 2.7 psutil-2.0.0 : https://pypi.python.org/pypi/psutil
* Python 2.7 pyzmq-2.2.0 : https://github.com/downloads/zeromq/pyzmq/pyzmq-2.2.0.win32-py2.7.msi
* Python 2.7 PySVN 1.7.8-1546 : http://pysvn.tigris.org/files/documents/1233/49313/py27-pysvn-svn1711-1.7.8-1546.exe
* dnspython : http://www.dnspython.org/
* pywin32 : http://sourceforge.net/projects/pywin32/
* flask + dependences : http://flask.pocoo.org/
* kerberos_sspi : https://github.com/may-day/kerberos-sspi
* flask_kerberos_sspi : https://flask-kerberos.readthedocs.org/en/latest/
* pefile : https://code.google.com/p/pefile/
* active_directory : http://timgolden.me.uk/python/active_directory.html
* wmi : http://timgolden.me.uk/python/wmi/index.html
* winshell : https://github.com/tjguk/winshell

Environnement CodeTyphon / Lazarus
---------------------
Base fpc+lazarus (dans la pratique, on installe CodeTyphon) : 

* fpc 2.7.1 Rev 27327
* lazarus SVN Rev 44546

Les bibliothèques tierces freepascal / lazarus utilisées : 

* indy : pl_indy : http://www.pilotlogic.com/sitejoom/index.php/wiki/85-wiki/codetyphon-studio/ct-packages/271-pl-indy
* superobject : https://code.google.com/p/superobject/
* virtualtrees : pl_virtualtrees http://www.pilotlogic.com/sitejoom/index.php/85-wiki/codetyphon-studio/ct-packages/301-pl-virtualtrees https://svn.code.sf.net/p/lazarus-ccr/svn/components/virtualtreeview-new/trunk/
* python4delphi : https://code.google.com/p/python4delphi/
* delphizmq : https://github.com/bvarga/delphizmq
* JCL : http://wiki.delphi-jedi.org/wiki/JCL_Installation
* thmtlport : https://svn.code.sf.net/p/lazarus-ccr/svn/components/thtmlport

Packages TIS : 
---------------
* pltis_python4delphi : https://github.com/tranquilit/pltis_python4delphi
* pltis_utils : https://github.com/tranquilit/pltis_utils : subset of libraries from JEDI JCL project adapted to lazarus
* pltis_sogrid : https://github.com/tranquilit/pltis_sogrid
* pltis_superobject : https://github.com/tranquilit/pltis_superobject

Construire WAPT avec CodeTyphon 4.8
================================

CodeTyphon est un Lazarus accompagné (entre autres) de nombreuses librairies, ce qui facilite la mise en place d'un IDE riche.

* Télécharger codetyphon 4.8 
* Dézipper vers c:\
* **Vérifier que cygwin n'est pas dans votre PATH global**. Si oui, retirer le au moins temporairement pour la compilation initiale de Codetyphon.
* Lancer c:\CodeTyphonIns\install.bat
* Choisir l'option 0
* Lancer Codetyphon Center
* Lancer Typhon-IDE /Typhon32 - Build BigIDE
* Lancer le bigide depuis CodeTyphon Center

Installer Git ou TortoiseGit

Checkout du projet et de ses composants :
------------
<pre>
cmd.exe
mkdir c:\tranquilit
git clone https://github.com/tranquilit/WAPT.git
git clone https://github.com/tranquilit/pltis_utils.git
git clone https://github.com/tranquilit/pltis_superobject.git
git clone https://github.com/tranquilit/pltis_sogrid.git
git clone https://github.com/tranquilit/pltis_python4delphi.git
git clone https://github.com/tranquilit/delphizmq.git
svn co https://svn.code.sf.net/p/lazarus-ccr/svn/components/thtmlport thtmlport

</pre>


Installation des paquets TIS dans Codetyphon
-------------------------

* Lancer codetyphon
* Paquet / Ouvrir un fichier paquet (.lpk)

Ouvrir successivement les paquets suivants, et les compiler.

* pltis_utils.lpk
* pltis_superobject.lpk
* pltis_sogrid.lpk (installation dans l'IDE nécessaire)
* pltis_python4delphi.lpk (installation dans l'IDE)
* pltis_delphizmq.lpk
* thtmlport\package\htmlcomp.lpk

Compilation exécutables 
----------------

* c:\tranquilit\wapt\wapt-get\waptget.lpr
* c:\tranquilit\wapt\waptconsole\waptconsole.lpr
* c:\tranquilit\wapt\wapttray\wapttray.lpr
* c:\tranquilit\wapt\waptexit\waptexit.lpr
* c:\tranquilit\wapt\waptdeploy\waptdeploy.lpr
* c:\tranquilit\wapt\waptserver\postconf\waptserverpostconf.lpr

Créer les installeurs
--------------------

* Installer Innosetup : http://www.jrsoftware.org/download.php/ispack-unicode.exe 
* Les fichiers .iss se situent dans c:\tranquilit\wapt\waptsetup\

L'installeur waptsetup inclut les bibliothèques python, l'outil en ligne de commande, le webservice local waptservice, les outils de packaging et la console centrale Wapt
 C:\tranquilit\WAPT\waptsetup\waptsetup.iss
 
Le fichier waptserver.iss permet de construire un installeur qui inclut un serveur apache en frontal pour le webservice Flask waptserver.py 
 C:\tranquilit\WAPT\waptsetup\waptserver.iss

L'installeur waptstarter n'inclut que le code pour le webservice local et l'outil en ligne de commande, mais pas la console centrale Wapt ni les outils de packaging.
 C:\tranquilit\WAPT\waptsetup\waptstarter.iss

Clic-droit sur le fichier iss / compile doit créer un installeur avec innosetup.

ou en ligne de commande :

```"C:\Program Files (x86)\Inno Setup 5\ISCC.exe" C:\tranquilit\wapt\waptsetup\waptsetup.iss```

Les paramètres généraux des installeurs sont définis par des #define en tête de fichier.

Si vous ne signez pas les installeur, vous pouvez commenter les lignes #define signtool ..

