#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import logging
import traceback

import ed25519
from nacl.public import PrivateKey, PublicKey
from nacl.encoding import HexEncoder as KeyFormatter
#from nacl.encoding import URLSafeBase64Encoder as KeyFormatter

from .crypt4gh import encrypt, decrypt, reencrypt
from .cli import parse_args
from .keys import generate_ec, generate_signing

LOG = logging.getLogger(__name__)

DEFAULT_PK   = os.getenv('C4GH_PUBLIC_KEY', None)
DEFAULT_SK   = os.getenv('C4GH_SECRET_KEY', None)
DEFAULT_SIGK = os.getenv('C4GH_SIGNING_KEY', None)

def run(args):

    # Parse CLI arguments
    args = parse_args(args)

    #####################################
    ## For Encryption
    ##################################### 
    if args['encrypt']:

        # If we want to sign the header
        signing_key = args['--signing_key'] or DEFAULT_SIGK
        if signing_key: # and os.path.exists(signing_key):
            with open(signing_key, 'rb') as f:
                signing_key = ed25519.SigningKey(f.read())

        pubkey = args['--pk'] or DEFAULT_PK
        if pubkey: # and os.path.exists(signing_key):
            with open(pubkey, 'rb') as f:
                pubkey = PublicKey(f.read(), KeyFormatter)
            
        encrypt(sys.stdin.buffer, sys.stdout.buffer, pubkey, signing_key=signing_key)
    
    #####################################
    ## For Decryption
    ##################################### 
    if args['decrypt']:

        seckey = args['--sk'] or DEFAULT_SK
        if not seckey or not os.path.exists(seckey):
            raise ValueError('Secret key not found')
        with open(seckey, 'rb') as skfile:
            seckey = PrivateKey(skfile.read(), KeyFormatter)

            # from getpass import getpass
            # passphrase = getpass(prompt=f'Passphrase for {args["--sk"]}: ')
            
            # hashlib.pbkdf2_hmac('sha256', passphrase.encode(), os.random(16), 100000, dklen=32)

            # hmac.digest(key, encrypted_seckey, digest=hashlib.sha256)
            # md = hmac.new(passphrase, encrypted_seckey)
            # passphrase = hmac.new(passphrase, seckey)
            # seckey = unlock(seckey, passphrase)

            decrypt(seckey, sys.stdin.buffer, process_output=sys.stdout.buffer.write)

    #####################################
    ## For ReEncryption
    #####################################
    if args['reencrypt']:

        signing_key = args['--signing_key'] or DEFAULT_SIGK
        if signing_key: # and os.path.exists(signing_key):
            with open(signing_key, 'rb') as f:
                signing_key = ed25519.SigningKey(f.read())

        pubkey = args['--pk'] or DEFAULT_PK
        if not pubkey or not os.path.exists(pubkey):
            raise ValueError('Public key not found')
        seckey = args['--sk'] or DEFAULT_SK
        if not seckey or not os.path.exists(seckey):
            raise ValueError('Secret key not found')
        with open(seckey, 'rb') as skfile, open(pubkey, 'rb') as pkfile:
            seckey = PrivateKey(skfile.read(), KeyFormatter)
            pubkey = PublicKey(pkfile.read(), KeyFormatter)
            # Same thing, unlock the key
            reencrypt(pubkey, seckey, sys.stdin.buffer, signing_key=signing_key, process_output=sys.stdout.buffer.write)

    #####################################
    ## For Keys Generation
    #####################################
    if args['generate']:

        seckey = args['-f']
        if os.path.isfile(seckey):
            yn = input(f'{seckey} already exists. Do you want to overwrite it? (y/n)')
            if yn != 'y':
                print('Ok. Fair enough. Exiting.')
                #sys.exit(0)
                return

        pubkey = args['-f'] + '.pub'
        passphrase = args['-P']

        if args['--signing']:
            generate_signing(seckey, pubkey, passphrase=passphrase)
        else:
            generate_ec(seckey, pubkey, passphrase=passphrase)


def main(args=sys.argv[1:]):
    try:
        run(args)
    except KeyboardInterrupt:
        pass
    # except Exception as e:
    #     _, _, exc_tb = sys.exc_info()
    #     traceback.print_tb(exc_tb, file=sys.stderr)
    #     sys.exit(1)

if __name__ == '__main__':
    main()
