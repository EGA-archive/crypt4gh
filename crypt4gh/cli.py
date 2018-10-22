# -*- coding: utf-8 -*-

import sys
import os
import logging
import logging.config

from docopt import docopt

from . import __title__, __version__

PROG = 'lega-cryptor'
DEFAULT_LOG = os.getenv('LEGA_LOG', None)

__doc__ = f'''

LocalEGA utilities for the cryptographic GA4GH standard.
Reads from stdin and Outputs to stdout

Usage:
   {PROG} [-hv] [--log <file>] encrypt [--signing_key <file>] [--pk <path>]
   {PROG} [-hv] [--log <file>] decrypt [--sk <path>]
   {PROG} [-hv] [--log <file>] reencrypt [--signing_key <file>] [--sk <path>] [--pk <path>]
   {PROG} [-hv] [--log <file>] generate [-f <path>] [-P <passphrase>] [--signing]

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <file>           Path to the logger file (in YML format)
   --pk <keyfile>         Public Curve25519 key to be used for encryption
   --sk <keyfile>         Private Curve25519 key to be used for decryption
   --signing_key <file>   Ed25519 Signing key for the header
   -f <path>              Private Curve25519 key (.pub is appended for the Public one) [default: ~/.lega/ega.key]
   -P <passphrase>        Passphrase to lock the secret key [default: None]
   --signing              Generate an ed25519 signing/verifying keypair

Environment variables:
   LEGA_LOG         If defined, it will be used as the default logger
   LEGA_PUBLIC_KEY  If defined, it will be used as the default public key (ie --pk ${{LEGA_PUBLIC_KEY}})
   LEGA_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${{LEGA_SECRET_KEY}})
   LEGA_SIGNING_KEY If defined, it will be used as the default signing key (ie --signing_key ${{LEGA_SIGNING_KEY}})

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
            logging.config.dictConfig(yaml.load(stream))

    # I prefer to clean up
    for s in ['--log', '--help', '--version']:#, 'help', 'version']:
        del args[s]

    # print(args)
    return args
