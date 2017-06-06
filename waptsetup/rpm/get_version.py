import pefile
#print('Getting version from executable')
WAPTSETUP = 'waptsetup-tis.exe'
pe = pefile.PE(WAPTSETUP)
version = pe.FileInfo[0].StringTable[0].entries['ProductVersion'].strip()
#print('%s version: %s', WAPTSETUP, version)
print  version
