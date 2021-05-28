#!/usr/bin/env python

import os


# Docker IP pointing to the host.
TARGET_IP = os.getenv('TARGET_IP', '172.17.0.1')
TARGET_PORT = os.getenv('TARGET_PORT', 31337)
