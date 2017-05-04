#!/usr/bin/python
#-*- coding: utf-8 -*-
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

#import des bibliothèque nécessaire
from waptpackage import *
import unittest

##tuto : https://openclassrooms.com/courses/apprenez-a-programmer-en-python/les-tests-unitaires-avec-unittest
##doc : https://docs.python.org/3/library/unittest.html

##=========
##TODO
##=========

class Test_Setup_Helpers(unittest.TestCase):

    def setUp(self):
        self.rrrr="dogflijdsdkjsofds"#parce que

    def test_md5_for_file(self):
        self.assertEqual('d41d8cd98f00b204e9800998ecf8427e',md5_for_file(r'C:\tranquilit\wapt\tests\FileToEncrypt.txt'))


    def test_parse_major_minor_patch_build(self):
        self.assertEqual({'major': 7, 'minor': 7, 'packaging': '7', 'patch': 7, 'subpatch': 7},parse_major_minor_patch_build('7.7.7.7-7'))
        self.assertEqual({'major': 7, 'minor': 7, 'packaging': None, 'patch': 7, 'subpatch': 7},parse_major_minor_patch_build('7.7.7.7'))

    def test_make_version(self):
        self.assertEqual(u'7.7.7.7-7',make_version({'major': 7, 'minor': 7, 'packaging': '7', 'patch': 7, 'subpatch': 7}))
        self.assertEqual(u'7.7.7.7',make_version({'major': 7, 'minor': 7, 'packaging': None, 'patch': 7, 'subpatch': 7}))
        self.assertEqual(u'',make_version({'major': None, 'minor': None, 'packaging': None, 'patch': None, 'subpatch': None}))
        self.assertEqual(u'7.7',make_version({'major': None, 'minor': 7, 'packaging': None, 'patch': 7, 'subpatch': None}))

    def test_

if __name__ == "__main__":
    unittest.main()

