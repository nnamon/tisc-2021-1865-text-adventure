#!/bin/bash

cd "$(dirname "$0")"

export RAILS_ENV=test
rails server -b 127.0.0.1 -p 4000
