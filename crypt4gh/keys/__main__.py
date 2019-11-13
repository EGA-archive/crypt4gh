#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
#import traceback

from . import main

if __name__ == '__main__':
    assert sys.version_info >= (3, 6), "This tool requires python version 3.6 or higher"
    main()
