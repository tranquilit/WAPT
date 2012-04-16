import sys
import os
import zipfile 
import tempfile
import urllib2
import shutil

def psource(module):
 
    file = os.path.basename( module )
    dir = os.path.dirname( module )
 
    toks = file.split( '.' )
    modname = toks[0]
 
    # Check if dirrectory is really a directory
    if( os.path.exists( dir ) ):
 
    # Check if the file directory already exists in the sys.path array
        paths = sys.path
        pathfound = 0
        for path in paths:
            if(dir == path):
                pathfound = 1
 
    # If the dirrectory is not part of sys.path add it
        if not pathfound:
            sys.path.append( dir )
 
    exec ('import ' + modname) in globals()
 
    # reload the file to make sure its up to date
    exec( 'reload( ' + modname + ' )' ) in globals()
 
    # This returns the namespace of the file imported
    return modname

def download(url,destdir):
	"""Copy the contents of a file from a given URL
	to a local file.
	"""
	import urllib
	urllib.urlretrieve(url,destdir + '/' + url.split('/')[-1])

def ensure_dir(f):
    d = os.path.dirname(f)
    if not os.path.exists(d):
        os.makedirs(d)

wapt_repourl = 'http://srvintranet/'
packagecachedir = 'c:/tranquilit/cache/'
ensure_dir(packagecachedir)
wapttempdir = 'c:/tranquilit/tmp/'
ensure_dir (wapttempdir)

print ("starting installation")
sys.stdout.flush()
packagename = sys.argv[1]
print ("installing package " + packagename)
print ("download package from " + wapt_repourl)
sys.stdout.flush()

download( wapt_repourl + packagename , packagecachedir)
 
# When you import a file you must give it the full path
tempdirname = tempfile.mkdtemp(prefix=wapttempdir)
print ('unziping ' + packagecachedir +  '/' + packagename)
sys.stdout.flush()

zip = zipfile.ZipFile(packagecachedir +  '/' + packagename)
zip.extractall(path=tempdirname)

print ("sourcing install file")
sys.stdout.flush()

psource( tempdirname + '/' + 'setup.py' )
print ("executing install script")
sys.stdout.flush()

setup.install()

print ("install script finished")
print ("cleaning tmp dir")
sys.stdout.flush()

shutil.rmtree(tempdirname)

