#!/bin/bash

echo "Configuring cron" 
CRON_FILE=/etc/cron.d/waptrepo
if [ -f "$CRON_FILE" ]
then
  if ! grep -q  PATH "$CRON_FILE"
  then
    echo "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin" >> "$CRON_FILE"
  fi
  if ! grep -q  waptzsync.py "$CRON_FILE"
  then
    echo "30 21 * * * root /usr/bin/python /opt/waptrepo/waptzsync.py >> /var/log/waptzsync.log" >> "$CRON_FILE"
  fi
else
  echo "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
30 21 * * * root /usr/bin/python /opt/waptrepo/waptzsync.py >> /var/log/waptzsync.log" > "$CRON_FILE"
fi
echo "copy config-waptzsync.ini in /etc/tis/"
cp /opt/wapt/waptrepo/config-waptzsync.ini.template /etc/tis/config-waptzsync.ini
echo "Run /opt/wapt/waptrepo/waptzsync.py for the first sync"
