#!/bin/bash

find /tmp -user mouse -exec /usr/bin/rm -fr {} \;
find /dev/shm -user mouse -exec /usr/bin/rm -fr {} \;
find /var/tmp -user mouse -exec /usr/bin/rm -fr {} \;

find /tmp -user rabbit -exec /usr/bin/rm -fr {} \;
find /dev/shm -user rabbit -exec /usr/bin/rm -fr {} \;
find /var/tmp -user rabbit -exec /usr/bin/rm -fr {} \;

find /tmp -user hatter -exec /usr/bin/rm -fr {} \;
find /dev/shm -user hatter -exec /usr/bin/rm -fr {} \;
find /var/tmp -user hatter -exec /usr/bin/rm -fr {} \;
