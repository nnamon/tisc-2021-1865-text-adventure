#!/bin/bash

if [ $# -eq 0 ]; then
    cron
    (while true; do runuser -u $USER2 $BASE_DIR/pool-of-tears/run.sh; done) &
    xinetd -d
else
    exec "$@"
fi
