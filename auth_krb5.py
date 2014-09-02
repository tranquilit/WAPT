# Copyright 2012 Dominik Ruf <dominikruf@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

''' Automatically authenticate to servers protected with Kerberos/NTLM/SSPI (e.g. Active Directory)
'''

import urllib2
import httplib
import os
from base64 import encodestring, decodestring

from sspi import ClientAuth

class SSPIAuthHandler(urllib2.BaseHandler):
    """auth handler for urllib2 that does Kerberos/NTLM/SSPI HTTP Negotiate Authentication
    """

    handler_order = 480  # TODO: test this by enabling basic auth

    def __init__(self):
        pass

    def http_error_401(self, req, fp, code, msg, headers):
        supported_schemes = [s.strip() for s in headers.get("WWW-Authenticate", "").split(",")]
        #dns_domain = os.environ['USERDNSDOMAIN']
        dns_domain = 'tranquilit.local'
        if('Negotiate' in supported_schemes):
            try:
                ca = ClientAuth("Kerberos", targetspn='HTTP/%s@%s' % (req.host.split(':')[0], dns_domain), auth_info=None)
                out_buf = ca.authorize(None)[1]
                data = out_buf[0].Buffer
                auth = encodestring(data).replace("\012", "")
                req.add_header('Authorization', 'Negotiate' + ' ' + auth)
                return self.parent.open(req)
            except:
                if('Kerberos' not in supported_schemes):
                    # if we can not fall back to NTLM, report error
                    raise

auth_handler= SSPIAuthHandler()
opener = urllib2.build_opener(auth_handler)
urllib2.install_opener(opener)
response = urllib2.urlopen('http://srvwiki.tranquilit.local')
data = response.read()
myfile = open('c:\\toto.html','w')
myfile.write(data)
myfile.close()