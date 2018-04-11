#!/bin/bash
sudo -u wapt PYTHONPATH=/opt/wapt PYTHONHOME=/opt/wapt /opt/wapt/bin/python /opt/wapt/waptserver/wapthuey.py waptenterprise.waptserver.wsus_tasks.huey -w 2 -k thread $@

