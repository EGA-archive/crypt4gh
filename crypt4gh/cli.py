# -*- coding: utf-8 -*-

import sys
import os
import logging
import logging.config
from functools import partial
from getpass import getpass
import re

from docopt import docopt
from nacl.public import PrivateKey

from . import __title__, __version__, PROG
from . import lib
from .keys import get_public_key, get_private_key

LOG = logging.getLogger(__name__)

DEFAULT_SK  = os.getenv('C4GH_SECRET_KEY', '~/.c4gh/key')
DEFAULT_LOG = os.getenv('C4GH_LOG', None)

__doc__ = f'''

Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.

Usage:
   {PROG} [-hv] [--log <file>] encrypt [--sk <path>] --recipient_pk <path> [--range <start-end>]
   {PROG} [-hv] [--log <file>] decrypt [--sk <path>] [--sender_pk <path>] [--range <start-end>]
   {PROG} [-hv] [--log <file>] rearrange [--sk <path>] --range <start-end>
   {PROG} [-hv] [--log <file>] reencrypt [--sk <path>] --recipient_pk <path> [--sender_public_key <path>] [--trim]

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <file>           Path to the logger file (in YML format)
   --sk <keyfile>         Curve25519-based Private key [default: {DEFAULT_SK}]
   --recipient_pk <path>  Recipient's Curve25519-based Public key
   --sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (aka, signature)
   --range <start-end>    Byte-range either as  <start-end> or just <start> (Start included, End excluded)
   -t, --trim             Keep only header packets that you can decrypt


Environment variables:
   C4GH_LOG         If defined, it will be used as the default logger
   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${{C4GH_SECRET_KEY}})
   C4GH_PASSPHRASE  If defined, it will be used as the passphrase
                    for decoding the secret key, replacing the callback.
                    Note: this is insecure. Only used for testing
 
'''

def parse_args(argv=sys.argv[1:]):

    version = f'{__title__} (version {__version__})'
    args = docopt(__doc__, argv, help=True, version=version)

    # if args['version']: print(version); sys.exit(0)
    # if args['help']: print(__doc__.strip()); sys.exit(0)

    # Logging
    logger = args['--log'] or DEFAULT_LOG
    # for the root logger
    logging.basicConfig(stream=sys.stderr,
                        level=logging.CRITICAL,
                        format='[%(levelname)s] %(message)s')
    if logger and os.path.exists(logger):
        with open(logger, 'rt') as stream:
            import yaml
            logging.config.dictConfig(yaml.safe_load(stream))

    # I prefer to clean up
    for s in ['--log', '--help', '--version']:#, 'help', 'version']:
        del args[s]

    # print(args)
    return args


range_re = re.compile(r'([\d]+)-([\d]+)?')

def parse_range(args):
    r = args['--range']
    if not r:
        return (0, None)

    m = range_re.match(r)
    if m is None:
        raise ValueError(f"Invalid range: {args['--range']}")
    
    start, end = m.groups()  # end might be None
    start, end = int(start), (int(end) if end else None)
    span = end - start - 1 if end else None
    if not span:
        raise ValueError(f"Invalid range: {args['--range']}")
    return (start, span)

def retrieve_private_key(args):

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

    return get_private_key(seckeypath, cb)

def encrypt(args):
    assert( args['encrypt'] )

    range_start, range_span = parse_range(args)

    recipient_pubkey = os.path.expanduser(args['--recipient_pk'])
    if not os.path.exists(recipient_pubkey):
        raise ValueError("Recipient's Public Key not found")
    recipient_pubkey = get_public_key(recipient_pubkey)


    seckey = retrieve_private_key(args)

    keys = [(0, seckey, recipient_pubkey)] # keys = list of (method, privkey, recipient_pubkey=None)

    lib.encrypt(keys,
                sys.stdin.buffer,
                sys.stdout.buffer,
                offset = range_start,
                span = range_span)
    

def decrypt(args):
    assert( args['decrypt'] )

    sender_pubkey = get_public_key(os.path.expanduser(args['--sender_pk'])) if args['--sender_pk'] else None

    range_start, range_span = parse_range(args)

    seckey = retrieve_private_key(args)

    keys = [(0, seckey, None)] # keys = list of (method, privkey, recipient_pubkey=None)

    lib.decrypt(keys,
                sys.stdin.buffer,
                sys.stdout.buffer,
                offset = range_start,
                span = range_span,
                sender_pubkey=sender_pubkey)


def rearrange(args):
    assert( args['rearrange'] )

    range_start, range_span = parse_range(args)

    seckey = retrieve_private_key(args)

    keys = [(0, seckey, bytes(PrivateKey(seckey).public_key))] # keys = list of (method, privkey, recipient_pubkey=ourselves)

    lib.rearrange(keys,
                  sys.stdin.buffer,
                  sys.stdout.buffer,
                  offset = range_start,
                  span = range_span)

def reencrypt(args):
    assert( args['reencrypt'] )

    seckey = retrieve_private_key(args)

    recipient_pubkey = get_public_key(os.path.expanduser(args['--recipient_pk']))

    sender_pubkey = get_public_key(os.path.expanduser(args['--sender_pk'])) if args['--sender_pk'] else None

    lib.reencrypt([(0, seckey, None)], # sender_keys
                  [(0, seckey, recipient_pubkey)], # recipient_keys
                  sys.stdin.buffer,
                  sys.stdout.buffer,
                  trim=args['--trim'])
