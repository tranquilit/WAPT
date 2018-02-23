#!/bin/bash
sudo NCURSES_NO_UTF8_ACS=1 PYTHONHOME=/opt/wapt PYTHONPATH=/opt/wapt /opt/wapt/bin/python /opt/wapt/waptserver/scripts/postconf.py $@
