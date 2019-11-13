# -*- coding: utf-8 -*-

'''This module implements the public/private key format for Crypt4GH.'''

import sys
import os
import logging
import logging.config
from functools import partial
from getpass import getpass

from docopt import docopt

from .. import __title__, __version__, PROG
from . import get_public_key, get_private_key

LOG = logging.getLogger(__name__)

__doc__ = f'''
 
Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.

Usage:
   {PROG}-keygen-debug [-hv] [--verbose] pk <path>
   {PROG}-keygen-debug [-hv] [--verbose] sk <path>

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --verbose              Prints more output

'''


def main(argv=sys.argv[1:]):

    # Parse CLI arguments
    version = f'{__title__} (version {__version__})'
    args = docopt(__doc__, argv, help=True, version=version)

    # Logging
    d = {
        'version': 1,
        'root': { 'level': 'NOTSET',
                  'handlers': ['noHandler']},
        'loggers': {'__main__': {'level': 'INFO',
                                 'handlers': ['console'],
                                 'propagate': True },
                    'crypt4gh': {'level': 'INFO',
                                 'handlers': ['console'],
                                 'propagate': True },
        },
        'handlers': { 'noHandler': {'class': 'logging.NullHandler',
                                    'level': 'NOTSET'},
                      'console': {'class': 'logging.StreamHandler',
                                  'formatter': 'simple',
                                  'stream': 'ext://sys.stderr'}
        },
        'formatters': {'simple': {'format': '# {message}',
                                  'style': '{'} 
        }
    }

    if args['--verbose']:
        for logger in d['loggers'].values():
            logger['level'] = 'DEBUG'

    logging.config.dictConfig(d)

    keypath = os.path.expanduser(args['<path>'])

    if args['pk']:
        pubkey = get_public_key(keypath)
        LOG.info('Public Key: %s', pubkey.hex().upper())
        return

    if args['sk']:
        cb = partial(getpass, prompt=f'Passphrase for {args["<path>"]}: ')
        seckey = get_private_key(keypath, cb)
        LOG.info('Private Key: %s', seckey.hex().upper())

        # from nacl.public import PrivateKey
        # sk = PrivateKey(seckey)
        # assert( pubkey == bytes(sk.public_key) )
        return

    raise ValueError('Should not come here')

if __name__ == '__main__':
    assert sys.version_info >= (3, 6), "This tool requires python version 3.6 or higher"
    main()
