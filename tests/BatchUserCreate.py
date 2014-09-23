# BatchUserCreate.py
#
# A sample administrative script to perform a batch
# creation of many users.

# Input to this program is a text file with one user per
# line.  Each line contains the new username and the
# user's full name.

# Creates the new user, and a new share on the server
# for the user.  The new share is secure, and can only
# be accessed by the new user.
import win32security, win32net, win32file, win32api
import win32netcon, ntsecuritycon
import os, sys, string

# The name of the server to use to create the user.
serverName = None

# The logic for naming the home_drive assumes we have
# a server name.  If we dont, get the current machine name.
if serverName is None:
    serverName = "\\\\" + win32api.GetComputerName()

# The root of each users personal directory.
# This is a local reference to the directory where each
# personal directory is created.
homeRoot = "C:\\Users"

def CreateUserAndShare(userName, fullName):
    homeDir = "%s\\%s" % (serverName, userName)
    # Create user data in information level 3 (PyUSER_INFO_3) format.
    userData = {}
    userData['name'] = userName
    userData['full_name'] = fullName
    userData['password'] = userName
    userData['flags'] = win32netcon.UF_NORMAL_ACCOUNT | win32netcon.UF_SCRIPT
    userData['priv'] = win32netcon.USER_PRIV_USER
    userData['home_dir'] = homeDir
    userData['home_dir_drive'] = "P:"
    userData['primary_group_id'] = ntsecuritycon.DOMAIN_GROUP_RID_USERS
    userData['password_expired'] = 1 # User must change password next logon.

    # Create the user
    win32net.NetUserAdd(serverName, 3, userData)

    # Create the new directory, then the share
    dirName = os.path.join(homeRoot, userName)
    os.mkdir(dirName)
    shareData = {}
    shareData['netname'] = userName
    shareData['type'] = win32netcon.STYPE_DISKTREE
    shareData['path'] = dirName
    shareData['max_uses'] = -1
    # The security setting for the share.
    sd = CreateUserSecurityDescriptor(userName)
    shareData['security_descriptor'] = sd
    # And finally create it.
    win32net.NetShareAdd(serverName, 502, shareData)

# A utility function that creates an NT security object for a user.
def CreateUserSecurityDescriptor(userName):
    sidUser = win32security.LookupAccountName(serverName, userName)[0]
    sd = win32security.SECURITY_DESCRIPTOR()

    # Create the "well known" SID for the administrators group
    subAuths = ntsecuritycon.SECURITY_BUILTIN_DOMAIN_RID, \
               ntsecuritycon.DOMAIN_ALIAS_RID_ADMINS
    sidAdmins = win32security.SID(ntsecuritycon.SECURITY_NT_AUTHORITY, subAuths)

    # Now set the ACL, giving user and admin full access.
    acl = win32security.ACL(128)
    acl.AddAccessAllowedAce(win32file.FILE_ALL_ACCESS, sidUser)
    acl.AddAccessAllowedAce(win32file.FILE_ALL_ACCESS, sidAdmins)

    sd.SetSecurityDescriptorDacl(1, acl, 0)
    return sd

# Debug helper to delete our test accounts and shares.
def DeleteUser(name):
    try:    win32net.NetUserDel(serverName, name)
    except win32net.error: pass

    try: win32net.NetShareDel(serverName, name)
    except win32net.error: pass

    try: os.rmdir(os.path.join(homeRoot, name))
    except os.error: pass

if __name__=='__main__':
    import fileinput # Helper for reading files line by line
    if len(sys.argv)<2:
        print "You must specify an options file"
        sys.exit(1)
    if sys.argv[1]=="-delete":
        for line in fileinput.input(sys.argv[2:]):
            DeleteUser(string.split(line,",")[0])
    else:
        for line in fileinput.input(sys.argv[1:]):
            userName, fullName = string.split(string.strip(line), ",")
            CreateUserAndShare(userName, fullName)
            print "Created", userName