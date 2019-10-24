# -*- coding: utf-8 -*-

import sys
import os
import logging
import logging.config
from functools import partial
from getpass import getpass
import re

from docopt import docopt

from . import __title__, __version__, PROG
from . import engine
from .keys import get_public_key, get_private_key

LOG = logging.getLogger(__name__)

DEFAULT_SK  = os.getenv('C4GH_SECRET_KEY', '~/.c4gh/key')
DEFAULT_LOG = os.getenv('C4GH_LOG', None)

# We make the following choices for this utility.
#
# Even though the library can encrypt/decrypt/reencrypt for multiple users, and use multiple session keys,
# the command-line options allow only one recipient (ie --recipient_sk can not be repeated)
# and only one writer/sender. The code creates only one session key when encrypting a stream.
# This simplifies the code
#
# We do separate 'rearrange' from 'reencrypt', to make it simpler.
# If you want to combine them, pipe one into the other.
#
# Reencrypt has the option to "trim" the headers.
# That means, we toss away the packets that we can't decrypt, since they are targeting another user.
#
# Rearrange does not have that option, as changing the edit list packet for the current user might
# result in the data section not containing the same blocks.
#
# Range <start-end> is applied to the "decrypted file" (ie the original content, as if no encryption was applied).
# This needs to be combined with the edit list: First we apply (virtually) the edit list, and then apply the
# <start-end> chunking. We make the choice that you can only use one range, and not multiple ones, as in the edit list.

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
   --range <start-end>    Byte-range either as  <start-end> or just <start>
   -t, --trim             Keep only header packets that you can decrypt


Environment variables:
   C4GH_LOG         If defined, it will be used as the default logger
   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${{C4GH_SECRET_KEY}})

'''


def parse_args(argv=sys.argv[1:]):

    version = f'{__title__} (version {__version__})'
    args = docopt(__doc__, argv, help=True, version=version)

    # if args['version']: print(version); sys.exit(0)
    # if args['help']: print(__doc__.strip()); sys.exit(0)

    # Logging
    logger = args['--log'] or DEFAULT_LOG
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
    if end and start >= end:
        raise ValueError(f"Invalid range: {args['--range']}")
    return (start, end)

def encrypt(args):
    assert( args['encrypt'] )

    range_start, range_end = parse_range(args)

    recipient_pubkey = os.path.expanduser(args['--recipient_pk'])
    if not os.path.exists(recipient_pubkey):
        raise ValueError("Recipient's Public Key not found")
    recipient_pubkey = get_public_key(recipient_pubkey)


    seckey = args['--sk'] or DEFAULT_SK
    seckeypath = os.path.expanduser(seckey)
    if not os.path.exists(seckeypath):
        raise ValueError('Secret key not found')

    passphrase = os.getenv('C4GH_PASSPHRASE')
    if passphrase:
        LOG.warning("Using a passphrase in an environment variable is insecure")
        cb = lambda : passphrase
    else:
        cb = partial(getpass, prompt=f'Passphrase for {seckey}: ')

    seckey = get_private_key(seckeypath, cb)
    keys = [(0, seckey, recipient_pubkey)] # keys = list of (method, privkey, sender_pubkey=None)

    engine.encrypt(keys,
                   sys.stdin.buffer,
                   sys.stdout.buffer,
                   start_coordinate = range_start,
                   end_coordinate = range_end)


def decrypt(args):
    assert( args['decrypt'] )

    sender_pubkey = get_public_key(os.path.expanduser(args['--sender_pk'])) if args['--sender_pk'] else None

    range_start, range_end = parse_range(args)

    seckey = args['--sk'] or DEFAULT_SK
    seckeypath = os.path.expanduser(seckey)
    if not os.path.exists(seckeypath):
        raise ValueError('Secret key not found')

    passphrase = os.getenv('C4GH_PASSPHRASE')
    if passphrase:
        LOG.warning("Using a passphrase in an environment variable is insecure")
        cb = lambda : passphrase
    else:
        cb = partial(getpass, prompt=f'Passphrase for {seckey}: ')

    seckey = get_private_key(seckeypath, cb)
    keys = [(0, seckey, sender_pubkey)] # keys = list of (method, privkey, sender_pubkey=None)

    engine.decrypt(keys, # list of (method, privkey, sender_pubkey=None)
                   sys.stdin.buffer,
                   sys.stdout.buffer,
                   start_coordinate = range_start,
                   end_coordinate = range_end)


def rearrange(args):
    assert( args['rearrange'] )
    raise NotImplementedError()

def reencrypt(args):
    assert( args['reencrypt'] )

    seckey = args['--sk'] or DEFAULT_SK
    if not seckey:
        raise ValueError('Secret key not specified')
    seckey = os.path.expanduser(seckey)
    if not os.path.exists(seckey):
        raise ValueError('Secret key not found')
    cb = partial(getpass, prompt=f'Passphrase for {args["--sk"]}: ')
    seckey = get_private_key(seckey, cb)

    recipient_pubkey = get_public_key(os.path.expanduser(args['--recipient_pk']))
    sender_pubkey = get_public_key(os.path.expanduser(args['--sender_pk'])) if args['--sender_pk'] else None

    engine.reencrypt([(0, seckey, sender_pubkey)], # recipient_keys
                     [(0, seckey, recipient_pubkey)], # recipient_keys
                     sys.stdin.buffer, sys.stdout.buffer,
                     trim=args['--trim'])
