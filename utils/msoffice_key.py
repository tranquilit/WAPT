import sys
import string
import math
import _winreg as wr

#b24chrs = (string.digits + string.ascii_uppercase)[:24]
generic_b24chrs = '0123456789ABCDEFGHIJKLMN'

code_len = 25 # encoded key length (user-readable key)
bin_len = 15 # binary key length
regkey_idx = 52 # start of key in DPID for 2003, 2007
regkey_idx_2010 = 0x328 # start in DPID for 2010

b24chrs = 'BCDFGHJKMPQRTVWXY2346789'
reg_root = r'Software\Microsoft\Office'

def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def b24encode(input, outlen=None, chrmap=None):

    # The number of coded characters to actually generate can't be
    # determined soley from the input length, but we can guess.
    if outlen is None:
        # each base24 code char takes ~4.585 bits (ln24 / ln2)
        outlen = int(math.ceil(8*len(input) / 4.585))

    # Use default character mapping [0-9A-N] if none provided
    if chrmap is None:
        chrmap = generic_b24chrs

    input = [ord(i) for i in input[::-1]]
    '''
    # takes less memory (does it piecewise), but more complex
    decoded = []
    for i in range(0,encoded_chars + 1)[::-1]:
        r = 0
        for j in range(0,15)[::-1]:
            r = (r * 256) ^ input[j]
            input[j] = r / 24
            r = r % 24

        print b24chrs[r]
        decoded = decoded.append(b24chrs[r])

    return decoded[::-1]
    '''

    # simple, but eats a ton of memory and probably time if the
    # encoded string is large
    enc = 0
    for i in input:
        enc = enc * 256 + i

    dec = []
    for i in range(outlen):
        dec.append(chrmap[enc % 24])
        enc = enc // 24

    dec.reverse()
    return ''.join(dec)

def b24decode(input, chrmap=None):

    # Use default character mapping [0-9A-N] if none provided
    if chrmap is None:
        chrmap = generic_b24chrs

    # clean invalid characters from input (e.g. '-' (dashes) in product key)
    # and map to \x00 through \x23.
    rmchrs = []
    for i in xrange(256):
        if not chr(i) in chrmap:
            rmchrs.append(chr(i))
    tt = string.maketrans(chrmap, ''.join([chr(i) for i in xrange(24)]))
    input = input.translate(tt, ''.join(rmchrs))

    encnum = 0
    for cc in input:
        encnum *= 24
        encnum += ord(cc)

    enc = []
    while encnum:
        enc.append(encnum % 256)
        encnum = encnum // 256

    return ''.join([chr(i) for i in enc])

def msoKeyDecode(regkey, version=None):
    '''Decodes a registry key value, by extracting product key
    from bytes 52-66 and decoding.

    Office 2010 (14.0) appears to store the key at 0x328 to 0x337 in
    DPID.  The "Registration" tree is different (cluttered) versus
    other versions, and the DPID value is (exactly) 7 times longer than
    before (1148 bytes, up from 164).

    Tested with a 2010 full suite and a trial of Visio.

    Parameters:
    - regkey is a string containing the contents of "DigitalProductID"
    - version is the decimal version number given by the key directly
    under the "Office" key root
    '''
    if version is None:
        version = 11 # (default 2003, 2007 appears to be compatible.)

    if float(version) < 14:
        enckey = regkey[regkey_idx:regkey_idx+bin_len]
    else:
        enckey = regkey[regkey_idx_2010:regkey_idx_2010+bin_len]

    deckey = b24encode(enckey, code_len, chrmap=b24chrs)

    return '-'.join(list(chunks(deckey,5)))

def SubKeys(key):
    i = 0
    while True:
        try:
            subkey = wr.EnumKey(key, i)
            yield subkey
        except WindowsError: # [Error 259] No more data is available
            break
        i += 1

def KeyValues(key):
    i = 0
    while True:
        try:
            value = wr.EnumValue(key, i)
            yield value
        except WindowsError: # [Error 259] No more data is available
            break
        i += 1

def main(argv=None):
    '''Scans local Microsoft Office registry keys for DigitalProductID values
    and encodes the binary data in base24.

    Note: The given "Name:" of Office 2010 products is incorrect
    (may just provide a single program name), though the Product Key
    should be valid.
    '''
    if argv is None:
        argv = sys.argv

    mso_root = wr.OpenKey(wr.HKEY_LOCAL_MACHINE, reg_root)

    product_head = "Product Name"
    dpid_head = "Digital Product ID (key encoded in base24)"

    prod_keys = []

    for subkey in SubKeys(mso_root):
        # subkey always observed to be a version number (11.0, 12.0, 14.0...)
        # where a DPID will be found.
        for sub2key in SubKeys(
                wr.OpenKey(mso_root, subkey)):
            # sub2key always observed to be "Registration" when DPID is found
            for sub3key in SubKeys(
                    wr.OpenKey(wr.OpenKey(mso_root, subkey), sub2key)):
                # sub3key often some UUID ending in 0F:F1:CE
                dpid_found = False
                for keyvalue in KeyValues(
                        wr.OpenKey(wr.OpenKey(wr.OpenKey(
                            mso_root,
                                subkey),
                                sub2key),
                                sub3key)):
                    if keyvalue[0] == 'DigitalProductID':
                        dpid_found = True
                        dpid = keyvalue
                    if keyvalue[0] == 'ProductName':
                        name = keyvalue

                if dpid_found:
                    #print ("Product Name: %s\n"
                    #       "         Key: %s\n") % \
                    #      (name[1],
                    #       msoKeyDecode(dpid[1],subkey))

                    #print rf.format(name[1], msoKeyDecode(dpid[1],subkey))
                    prod_keys.append((name[1], msoKeyDecode(dpid[1],subkey)))

    rf = "{0:<%i} {1:<}" % (max([len(i[0]) for i in prod_keys]) + 3)

    print rf.format(product_head, dpid_head)
    print rf.format('-' * len(product_head),'-' * len(dpid_head))

    for prod_key in prod_keys:
        print rf.format(*prod_key)


if __name__ == "__main__":
    sys.exit(main())
