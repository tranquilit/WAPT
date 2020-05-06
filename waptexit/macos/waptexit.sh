#!/bin/bash

function shutdown()
{
  /usr/local/bin/wapt-get upgrade
  exit 0
}

function startup()
{
  # mkfifo /tmp/wait-fifo; read < /tmp/wait-fifo # may be more optimized 
  tail -f /dev/null &

  wait $!
}

trap shutdown SIGTERM SIGKILL SIGINT

startup;
