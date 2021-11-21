#!/bin/bash

cd "$(dirname "$0")"

export RAILS_ENV=production
export RAILS_MASTER_KEY=4184b0e9ae92e24444659411423a529a
rm -f /opt/wonderland/pool-of-tears/tmp/pids/server.pid
rails server -b 127.0.0.1 -p 4000
