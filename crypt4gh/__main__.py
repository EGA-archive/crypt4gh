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

    # Construct a header with random session key
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

    LOG.debug('Creating Crypt4GH header')
    h = header.construct(version, session_key, seqnum, seckey, recipient_keys)

    infile = sys.stdin.buffer
    outfile = sys.stdout.buffer

    if args.header:
        with open(args.header, 'wb') as hf: # let it raise exception on errors
            hf.write(h)
    else:
        outfile.write(h)

    return payload.encrypt(infile, outfile, session_key, seqnum) # if seqnum is None => v1, else v2
    

def decrypt(args):
    assert args.command == 'decrypt'

    seckey = cli.retrieve_private_key(args)
    sender_pubkey = cli.retrieve_sender(args)

    infile = sys.stdin.buffer
    outfile = sys.stdout.buffer

    version, session_keys, edit_list = header.deconstruct(infile, seckey,
                                                          sender_pubkey=sender_pubkey)

    return payload.decrypt(infile, outfile, session_keys, edit_list, version=version)


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
                         version= 2 if args.v2 else 1)
    outfile.write(h)

    # If header-only reencryption, we are done.
    if args.header_only:
        LOG.info(f'Header-only reencryption Successful')
        return
    
    # Stream the remainder
    LOG.info('Streaming the remainder of the file')
    LOG.debug('Chunk size: %s', args.chunksize)

    payload.fastcopy(sys.stdin.fileno(), sys.stdout.fileno(),
                     sys.stdin.buffer.read, sys.stdout.buffer.write,
                     args.chunksize)
    LOG.info('Re-encryption successful')


def main():
    try:

        args = cli.parse_args()

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
