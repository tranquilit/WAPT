#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

try:
    wapt_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

sys.path.insert(0,os.path.join(wapt_root_dir))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib'))
sys.path.insert(0,os.path.join(wapt_root_dir,'lib','site-packages'))

import hashlib

try:
    from passlib.hash import sha512_crypt
    has_passlib = True
except Exception:
    has_passlib = False

def derive_key(password):
    if has_passlib:
        print sha512_crypt.encrypt(password, rounds=100000)
    else:
        print hashlib.sha1(password).hexdigest()

if __name__ == '__main__':
    password = raw_input()
    derive_key(password)
