#!/usr/bin/env python

import os

ENABLE_SLEEPS = False if os.getenv('ENABLE_SLEEPS', 'True') == 'False' else True
ENABLE_ADMIN = True if os.getenv('ENABLE_ADMIN', 'False') == 'True' else False
RAINBOW = False
