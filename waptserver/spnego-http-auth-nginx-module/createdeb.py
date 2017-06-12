#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
#    WAPT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WAPT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WAPT.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------

from __future__ import print_function
import os
import glob
import sys
import stat
import shutil
import fileinput
import subprocess
import platform
import errno


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def replaceAll(file, searchExp, replaceExp):
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp, replaceExp)
        sys.stdout.write(line)


def rsync(src, dst, excludes=[]):
    rsync_option = " --exclude '*.pyc' --exclude '*~' --exclude '.svn' --exclude 'deb' --exclude '.git' --exclude '.gitignore' -a --stats"
    if excludes:
        rsync_option = rsync_option + \
            ' '.join(" --exclude '%s'" % x for x in excludes)
    rsync_source = src
    rsync_destination = dst
    rsync_command = '/usr/bin/rsync %s "%s" "%s"' % (
        rsync_option, rsync_source, rsync_destination)
    print(rsync_command, file=sys.stderr)
    os.system(rsync_command)

makepath = os.path.join
from shutil import copyfile

# wapt
wapt_source_dir = os.path.abspath('../..')

# waptrepo
source_dir = os.path.abspath('..')

if platform.system() != 'Linux':
    print("this script should be used on debian linux", file=sys.stderr)
    sys.exit(1)

if len(sys.argv) > 2:
    print("wrong number of parameters (0 or 1)", file=sys.stderr)
    sys.exit(1)

deb_revision = None
if len(sys.argv) >= 2:
    try:
        deb_revision = int(sys.argv[1])
        if deb_revision <= 0:
            raise Exception()
    except:
        print("wrong parameter `%s' (should be a positive integer)" %
              (sys.argv[1],), file=sys.stderr)
        sys.exit(1)

new_umask = 022
old_umask = os.umask(new_umask)
if new_umask != old_umask:
    print('umask fixed (previous %03o, current %03o)' %
          (old_umask, new_umask), file=sys.stderr)

for line in open('%s/waptserver.py' % source_dir):
    if line.strip().startswith('__version__'):
        wapt_version = line.split('=')[
            1].strip().replace('"', '').replace("'", "")

if not wapt_version:
    print(u'version not found in %s/waptserver.py' %
          os.path.abspath('..'), file=sys.stderr)
    sys.exit(1)

control_file = './builddir/DEBIAN/control'

for filename in glob.glob("tis-wapt-spnego-http-auth-nginx-module*.deb"):
    print("Removing %s" % filename, file=sys.stderr)
    os.remove(filename)

if os.path.exists("builddir"):
    shutil.rmtree("builddir")

print('creating the package tree', file=sys.stderr)
mkdir_p("builddir/DEBIAN")
mkdir_p("builddir/usr/lib/nginx/modules/")
mkdir_p("builddir/usr/share/nginx/modules-available/")
mkdir_p('builddir/etc/nginx/modules-enabled/')
# for some reason the virtualenv does not build itself right if we don't
# have pip systemwide...
subprocess.check_output(r'sudo apt-get install -y build-essential unzip libkrb5-dev libgeoip-dev libgd-dev libxslt1-dev libxml2-dev  libpcre3-dev', shell=True)

#ngx_http_auth_spnego_module.so
nginx_dir = 'nginx-1.10.3'

if os.path.exists(nginx_dir):
    shutil.rmtree(nginx_dir)
subprocess.check_output('rm -f nginx-*.tar.gz*', shell=True)

print(subprocess.check_output('wget http://nginx.org/download/nginx-1.10.3.tar.gz',shell=True))
print(subprocess.check_output('tar -zxvf nginx-1.10.3.tar.gz',shell=True))
print(subprocess.check_output('unzip -d %s spnego-http-auth-nginx-module-0c6ff3f.zip' % nginx_dir,shell=True))

config_cmd_orig = """--with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2' --with-ld-opt='-Wl,-z,relro -Wl,-z,now' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=/var/log/nginx/error.log --lock-path=/var/lock/nginx.lock --pid-path=/run/nginx.pid --modules-path=/usr/lib/nginx/modules --http-client-body-temp-path=/var/lib/nginx/body --http-fastcgi-temp-path=/var/lib/nginx/fastcgi --http-proxy-temp-path=/var/lib/nginx/proxy --http-scgi-temp-path=/var/lib/nginx/scgi --http-uwsgi-temp-path=/var/lib/nginx/uwsgi --with-debug --with-pcre-jit --with-ipv6 --with-http_ssl_module --with-http_stub_status_module --with-http_realip_module --with-http_auth_request_module --with-http_v2_module --with-http_dav_module --with-http_slice_module --with-threads --with-http_addition_module --with-http_geoip_module=dynamic --with-http_gunzip_module --with-http_gzip_static_module --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_xslt_module=dynamic --with-stream=dynamic --with-stream_ssl_module --with-mail=dynamic --with-mail_ssl_module """

config_dynamic_modules = """ --add-dynamic-module=/build/nginx-4hGAP1/nginx-1.10.3/debian/modules/nginx-auth-pam --add-dynamic-module=/build/nginx-4hGAP1/nginx-1.10.3/debian/modules/nginx-dav-ext-module --add-dynamic-module=/build/nginx-4hGAP1/nginx-1.10.3/debian/modules/nginx-echo --add-dynamic-module=/build/nginx-4hGAP1/nginx-1.10.3/debian/modules/nginx-upstream-fair --add-dynamic-module=/build/nginx-4hGAP1/nginx-1.10.3/debian/modules/ngx_http_substitutions_filter_module """

config_cmd = """./configure    %s  --add-dynamic-module=spnego-http-auth-nginx-module-master/""" % config_cmd_orig

###config_cmd = """./configure --with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2' --with-ld-opt='-Wl,-z,relro -Wl,-z,now' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=/var/log/nginx/error.log --lock-path=/var/lock/nginx.lock --pid-path=/run/nginx.pid --modules-path=/usr/lib/nginx/modules --http-client-body-temp-path=/var/lib/nginx/body --http-fastcgi-temp-path=/var/lib/nginx/fastcgi --http-proxy-temp-path=/var/lib/nginx/proxy --http-scgi-temp-path=/var/lib/nginx/scgi --http-uwsgi-temp-path=/var/lib/nginx/uwsgi --with-debug --with-pcre-jit --with-ipv6 --with-http_ssl_module --with-http_stub_status_module --with-http_realip_module --with-http_auth_request_module --with-http_v2_module --with-http_dav_module --with-http_slice_module --with-threads --with-http_addition_module --with-http_geoip_module=dynamic --with-http_gunzip_module --with-http_gzip_static_module --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_xslt_module=dynamic --with-stream=dynamic --with-stream_ssl_module --with-mail=dynamic --with-mail_ssl_module --add-dynamic-module=spnego-http-auth-nginx-module-master/"""

print(subprocess.check_output(config_cmd, shell=True, cwd= nginx_dir))
print(subprocess.check_output('make modules',shell=True,cwd=nginx_dir))
print(subprocess.check_output('cp ./objs/ngx_http_auth_spnego_module.so  ../builddir/usr/lib/nginx/modules/',shell=True,cwd=nginx_dir))
subprocess.check_output(r'echo "load_module \"/usr/lib/nginx/modules/ngx_http_auth_spnego_module.so\";"  > ./builddir/usr/share/nginx/modules-available/mod-http_auth_spnego.conf', shell=True)

print("adding symlink for spnego module", file=sys.stderr)
mkdir_p('builddir/usr/bin')
os.symlink('/usr/share/nginx/modules-available/mod-http_auth_spnego.conf',
           'builddir/etc/nginx/modules-enabled/50-mod-http_auth_spnego.conf')

print('copying control and postinst package metadata', file=sys.stderr)
copyfile('./DEBIAN/control', './builddir/DEBIAN/control')
copyfile('./DEBIAN/postinst', './builddir/DEBIAN/postinst')
copyfile('./DEBIAN/preinst', './builddir/DEBIAN/preinst')
deb_revision =0
try:
    deb_revision = subprocess.check_output('git rev-parse --short HEAD', shell=True)
    deb_revision = deb_revision.strip()
except Exception:
    print('Could not retrieve the hash of the current git commit.',
          file=sys.stderr)
    print(sys.stderr, 'Is git(1) installed?', file=sys.stderr)
    raise

deb_version = '1.1.0'
if deb_revision:
    deb_version += '-1~%s%s' % ('tis',deb_revision)

print('replacing the revision in the control file', file=sys.stderr)
replaceAll(control_file, '0.0.7', deb_version)

os.chmod('./builddir/DEBIAN/postinst', stat.S_IRWXU |
         stat.S_IXGRP | stat.S_IRGRP | stat.S_IROTH | stat.S_IXOTH)
os.chmod('./builddir/DEBIAN/preinst', stat.S_IRWXU |
         stat.S_IXGRP | stat.S_IRGRP | stat.S_IROTH | stat.S_IXOTH)

print('creating the Debian package', file=sys.stderr)
output_file = 'libnginx-mod-http-auth-spnego-%s.deb' % (deb_version)
dpkg_command = 'dpkg-deb --build builddir %s' % output_file
status = os.system(dpkg_command)
if status == 0:
    if os.path.exists('libnginx-mod-http-auth-spnego.deb'):
        os.unlink('libnginx-mod-http-auth-spnego.deb')
    os.symlink(output_file, 'libnginx-mod-http-auth-spnego.deb')
    #shutil.rmtree("builddir")
else:
    print('error while building package')
sys.exit(status)
