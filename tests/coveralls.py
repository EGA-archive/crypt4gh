#!/bin/env/python

import os
from subprocess import call
import sys

# Run converalls command only on Travis
# Solution provided by https://stackoverflow.com/questions/32757765/conditional-commands-in-tox-tox-travis-ci-and-coveralls

if __name__ == '__main__':
    if 'TRAVIS' in os.environ:
        rc = call('coveralls')
        sys.stdout.write("Coveralls report from TRAVIS CI.\n")
        raise SystemExit(rc)
    else:
        sys.stdout.write("Not on TRAVIS CI.\n")
