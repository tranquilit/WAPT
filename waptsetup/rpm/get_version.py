import pefile
WAPTSETUP = 'waptsetup-tis.exe'
pe = pefile.PE(WAPTSETUP)
version = pe.FileInfo[0].StringTable[0].entries['ProductVersion'].strip()
print(version)
