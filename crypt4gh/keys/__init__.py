# -*- coding: utf-8 -*-

'''This module implements the public/private key format for Crypt4GH.'''

import sys
import os
import io
import logging
import logging.config
from base64 import b64decode, b64encode
from getpass import getpass

from docopt import docopt


from .. import __title__, __version__, PROG
from . import ssh, c4gh

LOG = logging.getLogger(__name__)

DEFAULT_LOG = os.getenv('C4GH_LOG', None)
DEFAULT_PK  = os.getenv('C4GH_PUBLIC_KEY', '~/.c4gh/key.pub')
DEFAULT_SK  = os.getenv('C4GH_SECRET_KEY', '~/.c4gh/key')


__doc__ = f'''
 
Utility to create Crypt4GH-formatted keys.

Usage:
   {PROG}-keygen [-hv] [--log <file>] [-f] [--pk <path>] [--sk <path>] [--nocrypt] [-C <comment>]

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


Environment variables:
  +-------------------+--------------------------------------------------------------------------------------+
  | C4GH_LOG          | If defined, it will be used as the default logger                                    |
  +-------------------+--------------------------------------------------------------------------------------+
  | C4GH_PUBLIC_KEY   | If defined, it will be used as the default public key (ie --pk ${{C4GH_PUBLIC_KEY}})   |
  +-------------------+--------------------------------------------------------------------------------------+
  | C4GH_SECRET_KEY   | If defined, it will be used as the default secret key (ie --sk ${{C4GH_SECRET_KEY}})   |
  +-------------------+--------------------------------------------------------------------------------------+
 
'''




#######################################################################
## Loading
#######################################################################


def load_from_pem(filepath):
    with open(filepath, 'rb') as f:
        lines = []

        # Strip empty lines and newline characters
        for l in f.readlines():
            l = l.strip()
            if l:
                lines.append(l)

        if (not lines
            or not lines[0].startswith(b'-----BEGIN ')
            or not lines[-1].startswith(b'-----END ')
            ):
            raise ValueError('Not a PEM format')

        return b64decode(b''.join(lines[1:-1]))

def get_public_key(filepath):
    '''Read the public key from keyfile location.'''

    with open(filepath, 'rb') as f:
        lines = []

        # Strip empty lines and newline characters
        for l in f.readlines():
            l = l.strip()
            if l:
                lines.append(l)

        if not lines:
            raise ValueError('Empty key')

        line = lines[0]

        if b'CRYPT4GH' in line: # it's Crypt4GH key
            LOG.info('Loading a Crypt4GH public key')
            return b64decode(b''.join(lines[1:-1]))

        if line[:4] == b'ssh-': # It's an SSH key
            LOG.info('Loading an OpenSSH public key')
            return ssh.get_public_key(line)

    raise NotImplementedError('Unsupported key format')


def get_private_key(filepath, callback):
    '''Read the private key from keyfile location.

    If the private key is encrypted, the user will be prompted for the passphrase.
    '''
    data = load_from_pem(filepath)
    stream = io.BytesIO(data)
    magic_word = stream.read(len(c4gh.MAGIC_WORD)) # start with C4GH, it's smaller

    if magic_word == c4gh.MAGIC_WORD: # It's a Crypt4GH key
        LOG.info('Loading a Crypt4GH private key')
        return c4gh.parse_private_key(stream, callback)

    magic_word += stream.read(len(ssh.MAGIC_WORD)-len(c4gh.MAGIC_WORD))
    if magic_word == ssh.MAGIC_WORD: # It's an SSH key
        LOG.info('Loading an OpenSSH private key')
        return ssh.parse_private_key(stream, callback)[0] # we also return the pubkey
    
    raise ValueError('Invalid key format')


###################
### CLI
###################


def run(argv=sys.argv[1:]):

    # Parse CLI arguments
    version = f'{__title__} (version {__version__})'
    args = docopt(__doc__, argv, help=True, version=version)

    # Logging
    logger = args['--log'] or DEFAULT_LOG
    if logger and os.path.exists(logger):
        with open(logger, 'rt') as f:
            import json
            logging.config.dictConfig(json.load(f))

    # I prefer to clean up
    for s in ['--log', '--help', '--version']:#, 'help', 'version']:
        del args[s]

    # print(args)

    pubkey = os.path.expanduser(args['--pk'])
    seckey = os.path.expanduser(args['--sk'])

    for k in (pubkey, seckey):
        if os.path.isfile(k):
            if not args['-f']: # Don't force
                yn = input(f'{k} already exists. Do you want to overwrite it? (y/n) ')
                if yn != 'y':
                    print('Ok. Fair enough. Exiting.')
                    #sys.exit(0)
                    return
            os.remove(k)

    comment = args['-C'].encode() if args['-C'] else None

    print("Generating public/private Crypt4GH key pair{}.".format(f" (for {args['-C']}" if comment else ""))
    passphrase1 = passphrase2 = None
    if not args['--nocrypt']:
        passphrase1 = getpass(prompt=f'Enter passphrase for {args["--sk"]} (empty for no passphrase): ').encode()
        passphrase2 = getpass(prompt=f'Enter passphrase for {args["--sk"]} (again): ').encode()

    if passphrase1 != passphrase2: # including None=None
        print('Passphrases do not match', file=sys.stderr)
        return 1

    c4gh.generate(seckey, pubkey, passphrase=passphrase1, comment=comment)
    print("Your private key has been saved in", seckey)
    print("Your public key has been saved in", pubkey)
    return 0

def main(argv=sys.argv[1:]):
    try:
        sys.exit(run(argv))
    except KeyboardInterrupt:
        pass
    # except Exception as e:
    #     import traceback
    #     _, _, exc_tb = sys.exc_info()
    #     traceback.print_tb(exc_tb, file=sys.stderr)
    #     sys.exit(1)

if __name__ == '__main__':
    assert sys.version_info >= (3, 6), "This tool requires python version 3.6 or higher"
    main()
