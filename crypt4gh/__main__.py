#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import logging
import traceback

import ed25519
from nacl.public import PrivateKey, PublicKey
from nacl.encoding import Base64Encoder

from .crypt4gh import encrypt, decrypt, reencrypt
from .cli import parse_args
from .keys import generate_ec, read as read_key

LOG = logging.getLogger(__name__)

DEFAULT_PK  = os.getenv('C4GH_PUBLIC_KEY', None)
DEFAULT_SK  = os.getenv('C4GH_SECRET_KEY', None)

def run(args):

    # Parse CLI arguments
    args = parse_args(args)

    #####################################
    ## For Encryption
    ##################################### 
    if args['encrypt']:

        pubkey = args['--pk'] or DEFAULT_PK
        seckey = args['--sk'] or DEFAULT_SK
        peer_pubkey = args['--ppk']
        if not pubkey or not seckey or not peer_pubkey:
            raise ValueError('CLI')
        
        pubkey = os.path.expanduser(pubkey)
        seckey = os.path.expanduser(seckey)
        peer_pubkey = os.path.expanduser(peer_pubkey)

        pubkey = read_key(pubkey)
        seckey = read_key(seckey)
        peer_pubkey = read_key(peer_pubkey)
            
        encrypt(pubkey, seckey, peer_pubkey, sys.stdin.buffer, sys.stdout.buffer)
    
    #####################################
    ## For Decryption
    ##################################### 
    if args['decrypt']:

        seckey = args['--sk'] or DEFAULT_SK
        if not seckey:
            raise ValueError('Secret key not specified')

        seckey = os.path.expanduser(seckey)

        seckey = read_key(seckey)
        # from getpass import getpass
        # passphrase = getpass(prompt=f'Passphrase for {args["--sk"]}: ')
            
        # hashlib.pbkdf2_hmac('sha256', passphrase.encode(), os.random(16), 100000, dklen=32)

        # hmac.digest(key, encrypted_seckey, digest=hashlib.sha256)
        # md = hmac.new(passphrase, encrypted_seckey)
        # passphrase = hmac.new(passphrase, seckey)
        # seckey = unlock(seckey, passphrase)

        decrypt(seckey, sys.stdin.buffer, sys.stdout.buffer)

    #####################################
    ## For ReEncryption
    #####################################
    if args['reencrypt']:

        signing_key = args['--signing_key'] or DEFAULT_SIGK
        if signing_key: # and os.path.exists(signing_key):
            signing_key = os.path.expanduser(signing_key)
            with open(signing_key, 'rt') as f: # hex format
                signing_key = ed25519.SigningKey(bytes.fromhex(f.read()))

        pubkey = os.path.expanduser(args['--pk'] or DEFAULT_PK)
        if not pubkey:
            raise ValueError('Public key not specified')
        pubkey = os.path.expanduser(pubkey)
        if not os.path.exists(pubkey):
            raise ValueError('Public key not found')

        seckey = args['--sk'] or DEFAULT_SK
        if not seckey:
            raise ValueError('Secret key not specified')
        seckey = os.path.expanduser(seckey)
        if not os.path.exists(seckey):
            raise ValueError('Secret key not found')

        with open(seckey, 'rt') as skfile, open(pubkey, 'rt') as pkfile:  # hex format
            seckey = PrivateKey(skfile.read(), HexEncoder)
            pubkey = PublicKey(pkfile.read(), HexEncoder)
            # Same thing, unlock the key
            reencrypt(pubkey, seckey, sys.stdin.buffer, signing_key=signing_key, process_output=sys.stdout.buffer.write)

    #####################################
    ## For Keys Generation
    #####################################
    if args['generate']:

        pubkey = os.path.expanduser(args['--pk'])
        seckey = os.path.expanduser(args['--sk'])
        for k in (pubkey, seckey):
            if os.path.isfile(k):
                yn = input(f'{k} already exists. Do you want to overwrite it? (y/n) ')
                if yn != 'y':
                    print('Ok. Fair enough. Exiting.')
                    #sys.exit(0)
                    return

        passphrase = args['-P']
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
