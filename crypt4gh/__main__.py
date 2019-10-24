#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
#import traceback

from . import cli

def main(argv=sys.argv[1:]):
    try:

        # Parse CLI arguments
        args = cli.parse_args(argv)

        # Main Commands
        for command in ('encrypt', 'decrypt', 'rearrange', 'reencrypt'):
            if args.get(command):
                cmd = getattr(cli,command,None)
                if not cmd:
                    raise ValueError(f'Command {command} not found')
                cmd(args)
                return

    except KeyboardInterrupt:
        pass
    except ValueError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    # except Exception as e:
    #     _, _, exc_tb = sys.exc_info()
    #     traceback.print_tb(exc_tb, file=sys.stderr)
    #     sys.exit(1)

if __name__ == '__main__':
    assert sys.version_info >= (3, 6), "This tool requires python version 3.6 or higher"
    main()
