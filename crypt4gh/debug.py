#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import logging
import logging.config
from functools import partial
from getpass import getpass
#import traceback

from docopt import docopt

from . import __title__, __version__, PROG
from . import SEGMENT_SIZE
from .lib import CIPHER_DIFF
from .keys import get_public_key, get_private_key
from . import header

LOG = logging.getLogger(__name__)

DEFAULT_SK  = os.getenv('C4GH_SECRET_KEY', '~/.c4gh/key')
DEFAULT_LOG = os.getenv('C4GH_LOG', None)

__doc__ = f'''
 
Utility for the cryptographic GA4GH standard, reading from stdin.

This is only used for debugging

Usage:
   {PROG}-debug [-hv] [--log <file>] [--sk <path>] [--sender_pk <path>]

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <file>           Path to the logger file (in YML format)
   --sk <keyfile>         Curve25519-based Private key [default: {DEFAULT_SK}]
   --sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (aka, signature)


Environment variables:
   C4GH_LOG         If defined, it will be used as the default logger
   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${{C4GH_SECRET_KEY}})
 
'''

##############################################################
##
##   For debugging
##
##############################################################

def parse_args(argv=sys.argv[1:]):

    version = f'{__title__} (version {__version__})'
    args = docopt(__doc__, argv, help=True, version=version)

    # if args['version']: print(version); sys.exit(0)
    # if args['help']: print(__doc__.strip()); sys.exit(0)

    # Logging
    logger = args['--log'] or DEFAULT_LOG
    logging.basicConfig(stream=sys.stderr, level=logging.CRITICAL) # for the root logger
    if logger and os.path.exists(logger):
        with open(logger, 'rt') as stream:
            import yaml
            logging.config.dictConfig(yaml.safe_load(stream))

    # I prefer to clean up
    for s in ['--log', '--help', '--version']:#, 'help', 'version']:
        del args[s]

    # print(args)
    return args


def output(args):

    seckey = args['--sk'] or DEFAULT_SK
    seckeypath = os.path.expanduser(seckey)
    if not os.path.exists(seckeypath):
        raise ValueError('Secret key not found')

    passphrase = os.getenv('C4GH_PASSPHRASE')
    if passphrase:
        #LOG.warning("Using a passphrase in an environment variable is insecure")
        print("Warning: Using a passphrase in an environment variable is insecure", file=sys.stderr)
        cb = lambda : passphrase
    else:
        cb = partial(getpass, prompt=f'Passphrase for {seckey}: ')

    seckey = get_private_key(seckeypath, cb)

    sender_pubkey = get_public_key(os.path.expanduser(args['--sender_pk'])) if args['--sender_pk'] else None

    infile = sys.stdin.buffer
    keys = [(0, seckey, None)]

    edits = None
    for i, packet in enumerate(header.parse(infile), start=1):

        decrypted_packet = header.decrypt_packet(packet, keys, sender_pubkey=sender_pubkey)
        if decrypted_packet is None: # They all failed
            print('# packet not decryptable')
            continue

        # Here is a packet

        packet_type = decrypted_packet[:4]
        packet_content = decrypted_packet[4:]
            
        if packet_type == header.PACKET_TYPE_DATA_ENC:
            LOG.debug(f'# packet {i} content: {packet_content.hex()}')
            session_key = header.parse_enc_packet(packet_content)
            print(f'# packet {i} session key: {session_key.hex()}')

        elif packet_type == header.PACKET_TYPE_EDIT_LIST:
            if edits is not None: # reject files if many edit list packets
                raise ValueError('Invalid file: Too many edit list packets')
            edits = packet_content, i

        else:
            packet_type = int.from_bytes(packet_type, byteorder='little')
            print(f'Packet {i}: Invalid packet (type: {packet_type})')


    if edits is not None:
        LOG.debug(f'# Packet {edits[1]} Edit list: {edits[0].hex()}')
        edit_list = list(header.parse_edit_list_packet(edits[0]))
        print(f'# Packet {edits[1]} Edit list: {edit_list}')


    # Scanning through the remainder and print the number of data blocks
    chunk_size = SEGMENT_SIZE + CIPHER_DIFF # chunk = cipher segment
    count = 0
    while True:
        segment = infile.read(chunk_size)
        if not segment:
            break
        count +=1

    print(f'# The data section contains {count} blocks')



def main(argv=sys.argv[1:]):
    try:
        args = parse_args(argv)
        output(args)
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
