#!/usr/bin/env python

import os

ENABLE_SLEEPS = False if os.getenv('ENABLE_SLEEPS', 'True') == 'False' else True
RAINBOW = False
