# -*- coding: utf-8 -*-

import sys
import os
import logging
import logging.config

from docopt import docopt

from . import __title__, __version__, PROG

DEFAULT_LOG = os.getenv('C4GH_LOG', None)

__doc__ = f'''

Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.

Usage:
   {PROG} [-hv] [--log <file>] encrypt (--sk <path> | --kms_secret_id <id>) --recipient_pk <path>
   {PROG} [-hv] [--log <file>] decrypt (--sk <path> | --kms_secret_id <id>) [--sender_pk <path>] [--range <start-end>]
   {PROG} [-hv] [--log <file>] reencrypt (--sk <path> | --kms_secret_id <id>) --recipient_pk <path> [--sender_public_key <path>]
   {PROG} [-hv] [--log <file>] generate [-f] [--pk <path>] [--sk <path>] [--nocrypt] [-C <comment>] [-R <rounds>]

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <file>           Path to the logger file (in YML format)
   --sk <keyfile>         Curve25519-based Private key [default: ~/.c4gh/key]
   --pk <keyfile>         Curve25519-based Public key  [default: ~/.c4gh/key.pub]
   --kms_secret_id <id>   ID of secret key stored in AWS parameter store
   --recipient_pk <path>  Recipient's Curve25519-based Public key
   --sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (aka, signature)
   -C <comment>           Key's Comment
   --nocrypt              Do not encrypt the private key.
                          Otherwise it is encrypted in the Crypt4GH key format
   -R <rounds>            Numbers of rounds for the key derivation. Ignore it to use the defaults.
   -f                     Overwrite the destination files
   --range <start-end>    Byte-range either as  <start-end> or just <start>.

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
            logging.config.dictConfig(yaml.load(stream))

    # I prefer to clean up
    for s in ['--log', '--help', '--version']:#, 'help', 'version']:
        del args[s]

   #  print(args)
    return args
