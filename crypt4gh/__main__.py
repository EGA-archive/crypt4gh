#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
#import traceback
import os
import logging

from . import cli, payload, header

LOG = logging.getLogger('crypt4gh')

def encrypt(args):
    assert args.command == 'encrypt'

    recipient_keys = cli.retrieve_recipients(args)
    seckey = cli.retrieve_private_key(args, generate=True)
    timestamp = cli.retrieve_expiration(args)

q    # Construct a header with random session key
    version = 1
    session_key = os.urandom(32)
    seqnum = None

    if args.v2:
        version = 2
        seqnum = int.from_bytes(os.urandom(8), byteorder='little', signed=False)
        # We use 8 bytes directly, producing potentially large (wrapping) numbers
        # We can also use, as a good start, and probably avoiding wrapping around 2^64
        #     import random
        #     seqnum = random.randint(0, 1<<32)

    h = header.construct(version, seckey, recipient_keys,
                         session_key, seqnum, None, timestamp, args.uri))

    infile = sys.stdin.buffer
    outfile = sys.stdout.buffer

    if args.header:
        LOG.debug('Outputting Crypt4GH header to %s', args.header)
        with open(args.header, 'wb') as hf: # let it raise exception on errors
            hf.write(h)
    else:
        outfile.write(h)

    LOG.debug('Encrypting payload')
    return payload.encrypt(infile, outfile, session_key, seqnum) # if seqnum is None => v1, else v2
    

def decrypt(args):
    assert args.command == 'decrypt'

    seckey = cli.retrieve_private_key(args)
    sender_pubkey = cli.retrieve_sender(args)

    infile = sys.stdin.buffer
    outfile = sys.stdout.buffer

    version, data_encryptions, edits, _ = header.deconstruct(infile, seckey,
                                                             sender_pubkey=sender_pubkey)

    return payload.decrypt(infile, outfile, data_encryptions, edits, version=version)


def reencrypt(args):
    assert args.command == 'reencrypt'

    recipient_keys = cli.retrieve_recipients(args)
    seckey = cli.retrieve_private_key(args)
    sender_pubkey = cli.retrieve_sender(args)

    infile = sys.stdin.buffer
    outfile = sys.stdout.buffer

    # Decrypt and re-encrypt the header
    h = header.reencrypt(infile, seckey, recipient_keys,
                         sender_pubkey = sender_pubkey,
                         uri = args.uri,
                         version= 2 if args.v2 else 1)
    outfile.write(h)

    # If header-only reencryption, we are done.
    # This might discard remaining data from infile
    if args.header_only:
        LOG.info(f'Header-only reencryption successful')
        return
    
    LOG.info('Streaming the remainder of the file')
    payload.copy(infile, outfile, args.chunksize)


def main():
    try:

        args = cli.parse_args()

        LOG.debug('Command: %s', args.command)

        if args.command == 'encrypt':
            return encrypt(args)
        if args.command == 'decrypt':
            return decrypt(args)
        if args.command == 'reencrypt':
            return reencrypt(args)

        raise ValueError(f'Command {args.command} not found')

    except KeyboardInterrupt:
        pass
    except ValueError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    # except Exception as e:
    #     _, _, exc_tb = sys.exc_info()
    #     traceback.print_tb(exc_tb, file=sys.stderr)
    #     sys.exit(1)

if __name__ == '__main__':
    assert sys.version_info >= (3, 6), "This tool requires python version 3.6 or higher"
    main()
