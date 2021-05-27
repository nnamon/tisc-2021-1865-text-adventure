#!/bin/bash

export INVITATION_CODE=`cat /home/$USER3/invitation_code`
cd $BASE_DIR/a-mad-tea-party
# Instances only can last for 15 minutes.
timeout --foreground -k 5s 15m java -jar tea-party/target/tea-party-1.0-SNAPSHOT.jar 2>/dev/null
