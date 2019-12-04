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
from crypt4gh import header, lib, SEGMENT_SIZE

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

    seckey = get_private_key(seckeypath, cb)


    recipient_pubkey = os.path.expanduser(sys.argv[2])
    if not os.path.exists(recipient_pubkey):
        raise ValueError("Recipient's Public Key not found")
    recipient_pubkey = get_public_key(recipient_pubkey)

    keys = [(0, seckey, recipient_pubkey)]

    #############################################################
    # Preparing the encryption engine
    #############################################################
    encryption_method = 0 # only choice for this version
    session_key = os.urandom(32) # we use one session key for all blocks

    #############################################################
    # Output the header
    #############################################################
    packets = [ header.make_packet_data_enc(encryption_method, session_key),
                header.make_packet_data_edit_list(edits) ]
    header_packets = [encrypted_packet for packet in packets for encrypted_packet in header.encrypt(packet, keys)]
    header_bytes = header.serialize(header_packets)
    sys.stdout.buffer.write(header_bytes)

    #############################################################
    # Output the message
    #############################################################
    infile = io.BytesIO(message)
    outfile = sys.stdout.buffer
    
    segment = bytearray(SEGMENT_SIZE)
    while True:
        segment_len = infile.readinto(segment)

        if segment_len == 0: # finito
            break

        if segment_len < SEGMENT_SIZE: # not a full segment
            data = bytes(segment[:segment_len]) # to discard the bytes from the previous segments
            lib._encrypt_segment(data, outfile.write, session_key)
            break

        data = bytes(segment) # this is a full segment
        lib._encrypt_segment(data, outfile.write, session_key)


