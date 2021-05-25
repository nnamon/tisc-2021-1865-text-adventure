#!/bin/bash

cd "$(dirname "$0")"

export RAILS_ENV=production
rails server -b 127.0.0.1 -p 4000
