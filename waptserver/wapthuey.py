#! python
# -*- coding: utf-8 -*-

from huey import Huey
from huey.backends.sqlite_backend import SqliteQueue

queue = SqliteQueue('wapt', location='/tmp/wapthuey.sqlite')
huey = Huey(queue)
