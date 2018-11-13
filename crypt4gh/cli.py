# -*- coding: utf-8 -*-

import sys
import os
import logging
import logging.config

from docopt import docopt

from . import __title__, __version__

PROG = 'crypt4gh'
DEFAULT_LOG = os.getenv('C4GH_LOG', None)

__doc__ = f'''

LocalEGA utilities for the cryptographic GA4GH standard.
Reads from stdin and Outputs to stdout

Usage:
   {PROG} [-hv] [--log <file>] encrypt [--signing_key <file>] [--pk <path>]
   {PROG} [-hv] [--log <file>] decrypt [--sk <path>]
   {PROG} [-hv] [--log <file>] reencrypt [--signing_key <file>] [--sk <path>] [--pk <path>]
   {PROG} [-hv] [--log <file>] generate [-o <path>] [-P <passphrase>] [--signing] [-f PKCS8|SSH2|none]

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <file>           Path to the logger file (in YML format)
   --pk <keyfile>         Public Curve25519 key to be used for encryption [default: ~/.c4gh/key.pub]
   --sk <keyfile>         Private Curve25519 key to be used for decryption [default: ~/.c4gh/key]
   --signing_key <file>   Ed25519 Signing key for the header
   -o <path>              Private Curve25519 key (.pub is appended for the Public one) [default: ~/.c4gh/sign]
   -P <passphrase>        Passphrase to lock the secret key [default: None]
   --signing              Generate an ed25519 signing/verifying keypair
   -f <fmt>               Key format: PKCS8, SSH2, or none [default: none]

Environment variables:
   C4GH_LOG         If defined, it will be used as the default logger
   C4GH_PUBLIC_KEY  If defined, it will be used as the default public key (ie --pk ${{C4GH_PUBLIC_KEY}})
   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${{C4GH_SECRET_KEY}})
   C4GH_SIGNING_KEY If defined, it will be used as the default signing key (ie --signing_key ${{C4GH_SIGNING_KEY}})

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
