#!/bin/bash

cron

runuser -u $USER2 $BASE_DIR/pool-of-tears/run.sh &

xinetd -d
