#!/bin/bash

if [ $# -eq 0 ]; then
    cron
    runuser -u $USER2 $BASE_DIR/pool-of-tears/run.sh &
    xinetd -d
else
    exec "$@"
fi
