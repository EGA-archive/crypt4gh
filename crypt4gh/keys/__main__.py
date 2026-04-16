#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''This module implements the public/private key format for Crypt4GH.'''

import sys
assert sys.version_info >= (3, 6), "This tool requires python version 3.6 or higher"

import os
import io
import logging
from functools import partial
from getpass import getpass
from pathlib import Path

from docopt import docopt

from .. import __title__, __version__, PROG
from . import c4gh, get_public_key, get_private_key

LOG = logging.getLogger(__name__)

DEFAULT_LOG = os.getenv('C4GH_LOG', None)
DEFAULT_PK  = os.getenv('C4GH_PUBLIC_KEY', '~/.c4gh/key.pub')
DEFAULT_SK  = os.getenv('C4GH_SECRET_KEY', '~/.c4gh/key')


__doc__ = f'''
 
Utility to create Crypt4GH-formatted keys.

Usage:
   {PROG}-keygen [-hv] [--log <file>] [-f] [--pk <path>] [--sk <path>] [--nocrypt] [-C <comment>] [--relock]

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <file>           Path to the logger file (in YML format)
   --sk <keyfile>         Curve25519-based Private key [default: {DEFAULT_SK}]
   --pk <keyfile>         Curve25519-based Public key  [default: {DEFAULT_PK}]
   -C <comment>           Key's Comment
   --nocrypt              Do not encrypt the private key.
                          Otherwise it is encrypted in the Crypt4GH key format
                          (See https://crypt4gh.readthedocs.io/en/latest/keys.html)
   -f                     Overwrite the destination files
   --relock               Re-lock the private key with a new passphrase


Environment variables:
  +-------------------+--------------------------------------------------------------------------------------+
  | C4GH_LOG          | If defined, it will be used as the default logger                                    |
  +-------------------+--------------------------------------------------------------------------------------+
  | C4GH_PUBLIC_KEY   | If defined, it will be used as the default public key (ie --pk ${{C4GH_PUBLIC_KEY}})   |
  +-------------------+--------------------------------------------------------------------------------------+
  | C4GH_SECRET_KEY   | If defined, it will be used as the default secret key (ie --sk ${{C4GH_SECRET_KEY}})   |
  +-------------------+--------------------------------------------------------------------------------------+
 
'''


###################
### CLI
###################


def _main():

    # Parse CLI arguments
    version = f'{__title__} (version {__version__})'
    args = docopt(__doc__, sys.argv[1:], version=version)

    # Logging
    logger = args['--log'] or DEFAULT_LOG
    if logger and os.path.exists(logger):
        with open(logger, 'rt') as stream:
            from logging.config import dictConfig
            import json
            dictConfig(json.load(stream))

    # I prefer to clean up
    for s in ['--log', '--help', '--version']:#, 'help', 'version']:
        del args[s]

    # print(args)

    pubkey = Path(args['--pk']).expanduser()
    seckey = Path(args['--sk']).expanduser()
    comment = args['-C'].encode() if args['-C'] else None

    comment_message = f" (for {args['-C']})" if comment else ''

    if args['--relock']:

        print(f'Relocking secret key {args["--sk"]}{comment_message}.')

        if not seckey.exists():
            print(f'Secret key {seckey} not found', file=sys.stderr)
            sys.exit(1)

        old_passphrase = os.getenv('C4GH_PASSPHRASE')
        cb = partial(getpass, prompt=f'Passphrase for {args["--sk"]}: ') if old_passphrase is None else lambda: old_passphrase
        seckey_decrypted = get_private_key(str(seckey), cb)

        passphrase1 = passphrase2 = None
        if not args['--nocrypt']:
            passphrase1 = getpass(prompt=f'Enter new passphrase for {args["--sk"]} (empty for no passphrase): ').encode()
            passphrase2 = getpass(prompt=f'Enter new passphrase for {args["--sk"]} (again): ').encode()

        if passphrase1 != passphrase2: # including None=None
            print('Passphrases do not match', file=sys.stderr)
            sys.exit(1)
            # We don't check if old_passphrase is the same as passphrase1/2

        c4gh.relock(seckey, seckey_decrypted, passphrase1, comment)
        print('Your private key has been relocked in', seckey)
        return



    print(f"Generating public/private Crypt4GH key pair{comment_message}.")
    passphrase1 = passphrase2 = None
    if not args['--nocrypt']:
        passphrase1 = getpass(prompt=f'Enter passphrase for {args["--sk"]} (empty for no passphrase): ').encode()
        passphrase2 = getpass(prompt=f'Enter passphrase for {args["--sk"]} (again): ').encode()

    if passphrase1 != passphrase2: # including None=None
        print('Passphrases do not match', file=sys.stderr)
        sys.exit(1)

    for k in (pubkey, seckey):
        if k.is_file():
            if not args['-f']: # Don't force
                yn = input(f'{k} already exists. Do you want to overwrite it? (y/n) ')
                if yn != 'y':
                    print('Ok. Fair enough. Exiting.')
                    #sys.exit(0)
                    return
            os.remove(k)
        elif not k.parent.exists():
            yn = input(f'Create directory {k.parent}? (y/n) ')
            if yn != 'y':
                print('Ok. Fair enough. Exiting.')
                #sys.exit(0)
                return
            k.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    # ... and cue music
    c4gh.generate(seckey, pubkey, passphrase1, comment)
    print('Your private key has been saved in', seckey)
    print('Your public key has been saved in', pubkey)

def main():
    try:
        _main()
    except KeyboardInterrupt:
        print('... Interrupted', file=sys.stderr)
        sys.exit(1)
        

if __name__ == '__main__':
    main()
