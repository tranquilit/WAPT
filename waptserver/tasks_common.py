#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT Enterprise Edition
#    Copyright (C) 2017  Tranquil IT Systems https://www.tranquil.it
#    All Rights Reserved.
#
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
# -----------------------------------------------------------------------

from __future__ import absolute_import
from waptserver.config import __version__

import os
import sys

from waptserver.tasks import *

try:
    from waptenterprise.waptserver.wsus_tasks import *
    from waptenterprise.waptserver.repositories_tasks import *
    waptenterprise = True
except:
    waptenterprise = False