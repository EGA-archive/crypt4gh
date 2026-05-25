# -*- coding: utf-8 -*-

import sys
import os
import logging
from logging.config import dictConfig
import json
import argparse
from functools import partial
from getpass import getpass
from datetime import datetime

from . import __title__, __version__
from .keys import get_public_key, get_private_key

LOG = logging.getLogger(__name__)

DEFAULT_LOG  = os.getenv('C4GH_LOG', 'NOTSET')
DEFAULT_SK  = os.getenv('C4GH_SECRET_KEY', None)

def parse_args():

    parser = argparse.ArgumentParser(prog='crypt4gh',
                                     description = 'Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.',
                                     formatter_class = argparse.RawDescriptionHelpFormatter,
                                     allow_abbrev = False,
                                     epilog = '''\
Environment variables:
   C4GH_LOG         If defined, it will be used as the default logger level
   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${C4GH_SECRET_KEY})
''')

    parser.add_argument('-v', '--version', action='version', version=f'{__title__} (version {__version__})')
    parser.add_argument('--log', help='Path to the logger file (in JSON format)')

    subparsers = parser.add_subparsers(dest='command', required = True,
                                       help='use "crypt4gh <command> -h" for help')

    # create the parser for the "encrypt" command
    parser_encrypt = subparsers.add_parser('encrypt')
    parser_encrypt.add_argument('-2', action='store_true', dest='v2', default=False,
                                help='Use version 2')
    parser_encrypt.add_argument('--passphrase-from-env', metavar='<envvar>', dest='envvar',
                                help='Read the passphrase from environment variable "envvar".')
    parser_encrypt.add_argument('--sk', metavar='<path>', dest='sk',
                                help='Curve25519-based Private key. If missing, and C4GH_SECRET_KEY not specified, a random key is generated')
    parser_encrypt.add_argument('--recipient-pk', action='append', metavar='<path>', dest='recipients',
                                help="Recipient's Curve25519-based Public key")
    parser_encrypt.add_argument('--header', metavar='<path>', dest='header',
                                help="Where to write the header (default: stdout)")
    parser_encrypt.add_argument('--expiration', metavar='<data>', dest='expiration',
                                help="Expiration date (in ISO format)")

    # create the parser for the "decrypt" command
    parser_decrypt = subparsers.add_parser('decrypt')
    parser_decrypt.add_argument('--passphrase-from-env', metavar='<envvar>', dest='envvar',
                                help='Read the passphrase from environment variable "envvar".')
    parser_decrypt.add_argument('--sender-pk', metavar='<path>', dest='sender',
                                help="Peer's Curve25519-based Public key to verify provenance (akin to signature)")
    parser_decrypt.add_argument('--sk', metavar='<path>', dest='sk',
                                help='Curve25519-based Private key (default: environment variable C4GH_SECRET_KEY)')

    # create the parser for the "reencrypt" command
    parser_reencrypt = subparsers.add_parser('reencrypt')
    parser_reencrypt.add_argument('-2', action='store_true', dest='v2', default=False,
                                  help='Use version 2')
    parser_reencrypt.add_argument('--passphrase-from-env', metavar='<envvar>', dest='envvar',
                                  help='Read the passphrase from environment variable "envvar".')
    parser_reencrypt.add_argument('--sk', metavar='<path>', dest='sk',
                                  help='Curve25519-based Private key (default: environment variable C4GH_SECRET_KEY)')
    parser_reencrypt.add_argument('--sender-pk', metavar='<path>', dest='sender',
                                  help="Peer's Curve25519-based Public key to verify provenance (akin to signature)")
    parser_reencrypt.add_argument('--recipient-pk', action='append', metavar='<path>', dest='recipients',
                                  help="Recipient's Curve25519-based Public key")
    parser_reencrypt.add_argument('--header-only', action='store_true', dest='header_only', default=False,
                                  help='Whether the input data consists only of a header (default: false)')
    parser_reencrypt.add_argument('--chunk-size', metavar='<size>', dest='chunksize', type=int, default=1<<23,
                                  help='Buffer transfer size (in bytes)')

    args = parser.parse_args(sys.argv[1:])

    # Logging for the root logger
    logging.basicConfig(stream=sys.stderr,
                        level=logging.getLevelName(DEFAULT_LOG),
                        format='[%(module)s][%(levelname)s] %(message)s')

    if args.log and os.path.exists(args.log):
        with open(args.log, 'rt') as stream:
            dictConfig(json.load(stream))

    return args


def retrieve_private_key(args, generate=False):

    seckey = args.sk or DEFAULT_SK

    if generate and seckey is None: # generate one on the fly
        skey = os.urandom(32)
        LOG.debug('Generating Private Key: %s', skey.hex().upper())
        return skey

    seckeypath = os.path.expanduser(seckey)
    if not os.path.exists(seckeypath):
        raise ValueError('Secret key not found')

    cb = partial(getpass, prompt=f'Passphrase for {seckey}: ')

    if args.envvar:
        passphrase = os.getenv(args.envvar)
        if passphrase:
            cb = lambda : passphrase # reset

    return get_private_key(seckeypath, cb)


def retrieve_recipients(args):

    # handle repetitions with a set,
    # in case different filenames are used for the same key
    recipient_keys = set()

    for pk in (args.recipients or []):
        recipient_pubkey = os.path.expanduser(pk)
        if not os.path.exists(recipient_pubkey):
            print(f"Recipient pubkey: {recipient_pubkey}, does not exist", file=sys.stderr)
            continue
        LOG.debug("Recipient pubkey: %s", recipient_pubkey)
        recipient_keys.add( get_public_key(recipient_pubkey) )

    if not recipient_keys:
        raise ValueError("No Recipients' Public Key found")

    return recipient_keys

def retrieve_sender(args):

    if args.sender:
        return get_public_key(os.path.expanduser(args.sender))

    return None

def retrieve_expiration(args):

    if args.expiration:
        LOG.debug("expiration: %s", args.expiration)
        return int(datetime.fromisoformat(args.expiration).timestamp())
    
    return None
