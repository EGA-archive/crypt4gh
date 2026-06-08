#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys
assert sys.version_info >= (3, 6), "This tool requires python version 3.6 or higher"

#import traceback
from random import randint
import os
import io
from functools import partial
from getpass import getpass

from crypt4gh.keys import get_private_key, get_public_key
from crypt4gh import sodium, header, payload

if __name__ == '__main__':

    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <seckey> <recipient_public_key>", file=sys.stderr)
        sys.exit(1)


    #############################################################
    # Build a message with random skip sizes in the middle
    #############################################################
    # We read stdin, line by line and strip the \n
    parts = [ line[:-1].encode() for line in sys.stdin if line[:-1] ]
    # Random skips in front of each part
    skips = [randint(10000, 100000) for p in parts]

    message = []
    edits = []
    for skip, part in zip(skips, parts):
        message.append(os.urandom(skip)) # adding rubbish data
        message.append(part)
        edits.append(skip)
        edits.append(len(part))
    message = b''.join(message)

    #############################################################
    # Fetch the keys
    #############################################################

    seckey = sys.argv[1]
    seckeypath = os.path.expanduser(seckey)
    if not os.path.exists(seckeypath):
        raise ValueError('Secret key not found')

    passphrase = os.getenv('C4GH_PASSPHRASE')
    if passphrase:
        #LOG.warning("Using a passphrase in an environment variable is insecure")
        print("Warning: Using a passphrase in an environment variable is insecure", file=sys.stderr)
        cb = lambda : passphrase
    else:
        cb = partial(getpass, prompt=f'Passphrase for {seckey}: ')


    recipient_pubkey = os.path.expanduser(sys.argv[2])
    if not os.path.exists(recipient_pubkey):
        raise ValueError("Recipient's Public Key not found")
    recipient_pubkey = get_public_key(recipient_pubkey)

    seckey = get_private_key(seckeypath, cb)
    pubkey = sodium.derive_pk(seckey)

    version = 1
    if len(sys.argv) > 3 and sys.argv[3] == '-2':
        version = 2

    #############################################################
    # Preparing the encryption engine
    #############################################################
    encryption_method = 0 # only choice for this version
    session_key = os.urandom(32) # we use one session key for all blocks

    seqnum = None
    if version == 2:
        seqnum = int.from_bytes(os.urandom(8), byteorder='little', signed=False)

    #############################################################
    # Output the header + message
    #############################################################
    infile = io.BytesIO(message)
    outfile = sys.stdout.buffer

    h = header.construct(version, seckey, [recipient_pubkey],
                         session_key, seqnum, edits, None, None)

    outfile.write(h)

    payload.encrypt(infile, outfile, session_key, None) # if seqnum is None => v1, else v2

