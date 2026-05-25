#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys
from datetime import datetime, timedelta

if __name__ == '__main__':

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <+/- seconds>", file=sys.stderr)
        sys.exit(1)

    now = datetime.now()
    t = now + timedelta(seconds=int(sys.argv[1]))
    s = t.strftime('%Y-%m-%d %H:%M:%S')
    print(s, end='')

    # print('now timestamp:', int(now.timestamp()))
    # print('res timestamp:', int(t.timestamp()))
    # print('timestamp:', int(datetime.fromisoformat(str(t)).timestamp()))
