#!/bin/bash

export INVITATION_CODE=`cat /home/$USER3/invitation_code`
cd $BASE_DIR/a-mad-tea-party && java -jar tea-party/target/tea-party-1.0-SNAPSHOT.jar
