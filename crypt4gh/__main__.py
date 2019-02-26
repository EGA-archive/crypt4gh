#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import logging
#import traceback
from functools import partial
from getpass import getpass

from .engine import encrypt, decrypt, reencrypt
from .cli import parse_args
from .keys import generate, get_public_key, get_private_key
from .aws import get_parameter

LOG = logging.getLogger(__name__)

DEFAULT_PK  = os.getenv('C4GH_PUBLIC_KEY', None)
DEFAULT_SK  = os.getenv('C4GH_SECRET_KEY', None)
tmp_pk_file = "pk.pem"

def run(args):
    # Parse CLI arguments
    args = parse_args(args)

    #####################################
    ## Retrieve private key
    ##################################### 
    if args['encrypt'] or args['decrypt'] or args['reencrypt']:
        if args['--kms_secret_id']:
            with open("pk.pem", 'w') as f: 
                f.write(get_parameter(args['--kms_secret_id']))
            seckey = tmp_pk_file
            cb = partial(getpass, prompt='Passphrase for {}: '.format(os.path.basename(args["--kms_secret_id"])))
        else:
            seckey = args['--sk'] or DEFAULT_SK
            if not seckey:
                raise ValueError('Secret key not specified')
            seckey = os.path.expanduser(seckey)
            if not os.path.exists(seckey):
                raise ValueError('Secret key not found')
            cb = partial(getpass, prompt='Passphrase for {}: '.format(os.path.basename(args["--sk"])))
        
        seckey = get_private_key(seckey, cb)

        try:
            os.remove(tmp_pk_file) #nuke temporary keyfile if it exists
        except OSError:
            pass

    #####################################
    ## For Encryption
    ##################################### 
    if args['encrypt']:
        recipient_pubkey = os.path.expanduser(args['--recipient_pk'])
        if not os.path.exists(recipient_pubkey):
            raise ValueError("Recipient's Public Key not found")
        recipient_pubkey = get_public_key(recipient_pubkey)
        encrypt(seckey, recipient_pubkey, sys.stdin.buffer, sys.stdout.buffer)
    
    #####################################
    ## For Decryption
    ##################################### 
    if args['decrypt']:

        kw = {}
        if args['--sender_pk']:
            kw['sender_pubkey'] = get_public_key(os.path.expanduser(args['--sender_pk']))

        if args['--range']:
            import re
            r = re.compile(r'([\d]+)-([\d]+)?')
            m = r.match(args['--range'])
            if m is None:
                raise ValueError(f"Invalid range: {args['--range']}")

            start, end = m.groups()  # end might be None
            start, end = int(start), (int(end) if end else None)
            if end and start >= end:
                raise ValueError(f"Invalid range: {args['--range']}")
            kw['start_coordinate'] = start
            kw['end_coordinate'] = end

        decrypt(seckey, sys.stdin.buffer, sys.stdout.buffer, **kw)

    #####################################
    ## For ReEncryption
    #####################################
    if args['reencrypt']:
        recipient_pubkey = get_public_key(os.path.expanduser(args['--recipient_pk']))
        sender_pubkey = get_public_key(os.path.expanduser(args['--sender_pk'])) if args['--sender_pk'] else None

        reencrypt(seckey, recipient_pubkey, sys.stdin.buffer, sys.stdout.buffer, sender_pubkey=sender_pubkey)

    #####################################
    ## For Keys Generation
    #####################################
    if args['generate']:

        pubkey = os.path.expanduser(args['--pk'])
        seckey = os.path.expanduser(args['--sk'])
        if not args['-f']: # Don't force
            for k in (pubkey, seckey):
                if os.path.isfile(k):
                    yn = input(f'{k} already exists. Do you want to overwrite it? (y/n) ')
                    if yn != 'y':
                        LOG.error('Ok. Fair enough. Exiting.')
                        sys.exit(0)
                
        do_crypt = not args['--nocrypt']
        cb = partial(getpass, prompt=f'Passphrase for {args["--sk"]}: ') if do_crypt else None
        rounds = int(args['-R']) if args['-R'] else None
        comment = args['-C'].encode() if args['-C'] else None
        generate(seckey, pubkey, callback=cb, comment=comment, rounds=rounds)


def main(args=sys.argv[1:]):
    try:
        run(args)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
