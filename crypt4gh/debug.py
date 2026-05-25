#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import logging
from logging.config import dictConfig
from functools import partial
from getpass import getpass
import json
from datetime import datetime
import argparse

from . import __title__, __version__, CIPHER_SEGMENT_SIZE
from . import cli, header

LOG = logging.getLogger(__name__)

DEFAULT_LOG  = os.getenv('C4GH_LOG', 'NOTSET')
DEFAULT_SK  = os.getenv('C4GH_SECRET_KEY', None)

##############################################################
##
##   For debugging
##
##############################################################

def parse_args():

    parser = argparse.ArgumentParser(prog='crypt4gh',
                                     description = 'Debugging utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.',
                                     formatter_class = argparse.RawDescriptionHelpFormatter,
                                     allow_abbrev = False,
                                     epilog = '''\
Environment variables:
   C4GH_LOG         If defined, it will be used as the default logger level
   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${C4GH_SECRET_KEY})
''')

    parser.add_argument('-v', '--version', action='version', version=f'{__title__} (version {__version__})')
    parser.add_argument('--log', help='Path to the logger file (in JSON format)')

    parser.add_argument('--passphrase-from-env', metavar='<envvar>', dest='envvar',
                        help='Read the passphrase from environment variable "envvar".')
    parser.add_argument('--sk', metavar='<path>', dest='sk',
                        help='Curve25519-based Private key. If missing, and C4GH_SECRET_KEY not specified, a random key is generated')
    parser.add_argument('--sender-pk', metavar='<path>', dest='sender',
                        help="Peer's Curve25519-based Public key to verify provenance (akin to signature)")


    args = parser.parse_args(sys.argv[1:])

    # Logging for the root logger
    logging.basicConfig(stream=sys.stderr,
                        level=logging.getLevelName(DEFAULT_LOG),
                        format='[%(module)s][%(levelname)s] %(message)s')

    if args.log and os.path.exists(args.log):
        with open(args.log, 'rt') as stream:
            dictConfig(json.load(stream))

    return args


def run(args):

    seckey = cli.retrieve_private_key(args)
    sender_pubkey = cli.retrieve_sender(args)

    infile = sys.stdin.buffer
    outfile = sys.stdout.buffer

    version, data_encryptions, edits, timestamp = header.deconstruct(infile, seckey,
                                                                     sender_pubkey=sender_pubkey)

    print('# Header version:', version)
    print('# Data encryption packets')
    for method, session_key, seqnum in data_encryptions:
        if method == 0:
            assert seqnum is None, "Invalid data encryption packet"
            print('   * session key:', session_key.hex())
        elif method == 1:
            print('   * session key:', session_key.hex())
            print('           start:', seqnum)
        else:
            print('   * medthod:', method, '|', session_key, '|', seqnum)

    if edits is not None:
        print('# Edit list:', edits)

    if timestamp is not None:
        expiration = datetime.fromtimestamp(timestamp)
        print('# Expiration:', expiration)

    # Scanning through the remainder and print the number of data blocks
    count = 0
    while segment := infile.read(CIPHER_SEGMENT_SIZE):
        count +=1

    print('# The data section contains', count, 'blocks')



def main():
    try:
        args = parse_args()
        run(args)
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
