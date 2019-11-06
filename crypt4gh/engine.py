# -*- coding: utf-8 -*-
"""Handle the encryption of the application data.

It encrypts or decrypts a given file read from stdin, and outputs the result to stdout.

It also reencrypts Crypt4GH-formatted input, into another Crypt4GH-formatted output.
"""

import os
import logging
import io
import collections

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from . import SEGMENT_SIZE
from . import convert_error, close_on_broken_pipe
from . import header, utils

LOG = logging.getLogger(__name__)

CIPHER_DIFF = 28

# Encryption Methods Conventions
# ------------------------------
#
# 0: chacha20_ietf_poly1305
# 1: AES-256-CTR => Not Implemented
# else: NotSupported


##############################################################
##
##    Symmetric encryption - Chacha20_Poly1305
##
##############################################################

def _encrypt_segment(data, process, cipher):
    '''Utility function to generate a nonce, encrypt data with Chacha20, and authenticate it with Poly1305.'''

    LOG.debug("Segment [%d bytes]: %s..%s", len(data), data[:10], data[-10:])

    nonce = os.urandom(12)
    encrypted_data = cipher.encrypt(nonce, data, None)  # No add
    process(nonce) # after producing the segment, so we don't start outputing when an error occurs
    process(encrypted_data)


@close_on_broken_pipe
def encrypt(keys, infile, outfile, offset=0, span=None):
    '''Encrypt infile into outfile, using the list of keys.


    It fast-forwards to `offset` and encrypts until
    a total of `span` bytes is reached (or to EOF if `span` is None)

    This produces a Crypt4GH file without edit list.
    '''

    LOG.info('Encrypting the file')

    # Forward to start position
    LOG.debug("  Start Coordinate: %s", offset)
    try:
        offset = int(offset)
        if offset < 0:
            offset = 0
            LOG.error('Invalid start coordinate. Using 0 instead')
    except Exception as e:
        LOG.error("Conversion error: %s", e)
        offset = 0

    if offset: # not 0
        LOG.info("Forwarding to position: %s", offset)
        infile.seek(offset, io.SEEK_SET)

    # Where to stop
    if isinstance(span, int) and span <= 0:
        LOG.error("    Span: %s | Converting to None", span)
        span = None

    LOG.debug("    Span: %s", span)

    # Preparing the encryption engine
    encryption_method = 0 # only choice for this version
    session_key = os.urandom(32) # we use one session key for all blocks
    cipher = ChaCha20Poly1305(session_key) # create a new one in case an old one is not reset

    # Output the header
    LOG.debug('Creating Crypt4GH header')
    header_content = header.make_packet_data_enc(encryption_method, session_key)
    header_packets = header.encrypt(header_content, keys)
    header_bytes = header.serialize(header_packets)

    LOG.debug('header length: %d', len(header_bytes))
    outfile.write(header_bytes)

    # ...and cue music
    LOG.debug("Streaming content")
    # oh boy... I buffer a whole segment!
    # TODO: Use a smaller buffer (Requires code rewrite)
    segment = bytearray(SEGMENT_SIZE)

    if span is None:
        # The whole file
        while True:
            segment_len = infile.readinto(segment)

            if segment_len == 0: # finito
                break

            if segment_len < SEGMENT_SIZE: # not a full segment
                data = bytes(segment[:segment_len]) # to discard the bytes from the previous segments
                _encrypt_segment(data, outfile.write, cipher)
                break

            data = bytes(segment) # this is a full segment
            _encrypt_segment(data, outfile.write, cipher)

    else: # we have a max size
        assert( span )

        while span > 0:

            segment_len = infile.readinto(segment)

            data = bytes(segment) # this is a full segment

            if segment_len < SEGMENT_SIZE: # not a full segment
                data = data[:segment_len] # to discard the bytes from the previous segments

            if span < segment_len: # stop early
                data = data[:span]
                _encrypt_segment(data, outfile.write, cipher)
                break

            _encrypt_segment(data, outfile.write, cipher)

            span -= segment_len

            if segment_len < SEGMENT_SIZE: # not a full segment
                break

    LOG.info('Encryption Successful')


##############################################################
##
##    Symmetric decryption - Chacha20_Poly1305
##
##############################################################

def cipher_chunker(f, size):
    while True:
        ciphersegment = f.read(size)
        ciphersegment_len = len(ciphersegment)
        if ciphersegment_len == 0: 
            break # We were at the last segment. Exits the loop
        assert( ciphersegment_len > CIPHER_DIFF )
        yield ciphersegment

def decrypt_block(ciphersegment, ciphers):
    # Trying the different session keys (via the cipher objects)
    # Note: we could order them and if one fails, we move it at the end of the list
    # So... LRU solution. For now, try them as they come.
    nonce = ciphersegment[:12]
    data = ciphersegment[12:]

    for cipher in ciphers:
        try:
            return cipher.decrypt(nonce, data, None)  # No aad, and break the loop
        except InvalidTag as tag:
            LOG.error('Decryption failed: %s', tag)
    else: # no cipher worked: Bark!
        raise ValueError('Could not decrypt that block')



@close_on_broken_pipe
def decrypt(keys, infile, outfile, sender_pubkey=None, offset=0, span=None):
    '''Decrypt infile into outfile, using a given set of keys.

    If sender_pubkey is specified, it verifies the provenance of the header.

    If no header packet is decryptable, it raises a ValueError
    '''
    LOG.info('Decrypting file | Range: [%s, %s[', offset, offset+span+1 if span else 'EOF')

    assert( # Checking the range
        isinstance(offset, int)
        and offset >= 0
        and (
            span is None
            or
            (isinstance(span, int) and span > 0)
        )
    )

    header_packets = header.parse(infile)
    packets, _ = header.decrypt(header_packets, keys, sender_pubkey=sender_pubkey)

    if not packets: # no packets were decrypted
        raise ValueError('No supported encryption method')

    data_packets, edit_packet = header.partition_packets(packets)
    # Parse returns the session key (since it should be method 0) 
    ciphers = [ChaCha20Poly1305(header.parse_enc_packet(packet)) for packet in data_packets]

    CIPHER_SEGMENT_SIZE = SEGMENT_SIZE + CIPHER_DIFF
                
    if edit_packet is None:
        # In this case, we try to fast-forward, and adjust the offset
        if offset > 0:
            start_segment, offset = divmod(offset, SEGMENT_SIZE)
            if start_segment: # not 0
                LOG.info('Fast-forwarding %d segment', start_segment)
                start_ciphersegment = start_segment * CIPHER_SEGMENT_SIZE
                infile.seek(start_ciphersegment, io.SEEK_CUR)  # move forward

    # Generator to slice the output
    output = utils.limited_output(offset=offset, limit=span, process=outfile.write)
    next(output) # start it

    try:
        if edit_packet is None:
            for ciphersegment in cipher_chunker(infile, CIPHER_SEGMENT_SIZE):
                segment = decrypt_block(ciphersegment, ciphers)
                output.send(segment)
        else:


            edits = collections.deque(header.parse_edit_list_packet(edit_packet))
            LOG.debug('Edit List: %s', edits)
            oracle = utils.edit_list_oracle(edits)
            next(oracle) # start it

            for i, ciphersegment in enumerate(cipher_chunker(infile, CIPHER_SEGMENT_SIZE)):

                segment_len = len(ciphersegment) - CIPHER_DIFF
                slices = oracle.send(segment_len)
                if slices is None:
                    LOG.warning('Cipherblock %d is entirely skipped', i)
                    continue

                LOG.debug('Edit List slices: %s', slices)
                segment = decrypt_block(ciphersegment, ciphers)
                LOG.debug('(------------------ HI OSCAR: %d == %d', id(slices), id([]))
                if slices == []: # no slices use all of it
                    LOG.debug('(------------------ HI OSCAR')
                    output.send(segment)
                    LOG.debug('(------------------ HI OSCAR')
                    continue

                assert (all( (y is None or x < y)  for x,y in slices)
                        and
                        all( slices[i][1] < slices[i+1][0] for i in range(len(slices)-1))
                ), f"Invalid slices: {slices}"
                for (x,y) in slices:
                    output.send(segment[x:] if y is None else segment[x:y]) # no copy if x=0, here!

    except utils.ProcessingOver:
        pass

    LOG.info('Decryption Over')


##############################################################
##
##    Just reencryption of the header
##
##############################################################


@close_on_broken_pipe
def reencrypt(keys, recipient_keys, infile, outfile, chunk_size=4096, trim=False):
    '''Extract header packets from infile and generate another one to outfile.
    The encrypted data section is only copied from infile to outfile.'''

    # Decrypt and re-encrypt the header
    header_packets = header.parse(infile)
    packets = header.reencrypt(header_packets, keys, recipient_keys, trim=trim)
    outfile.write(header.serialize(packets))

    # Stream the remainder
    LOG.info(f'Streaming the remainder of the file')
    while True:
        data = infile.read(chunk_size)
        if not data:
            break
        outfile.write(data)

    LOG.info('Reencryption Successful')


##############################################################
##
##   Adding or Updating an edit list in the header
##
##############################################################

@close_on_broken_pipe
def rearrange(keys, infile, outfile, offset=0, span=None):
    '''Extract header packets from infile, fetch the edit list if there was,
    and adds/updates it to reflect the [start;end] range.
    The new header is sent to the outfile.
    The encrypted data blocks are only copied from infile to outfile, if the edit list touches them.'''

    # Decrypt and re-encrypt the header
    header_packets = header.parse(infile)

    packets, segment_oracle = header.rearrange(header_packets, keys, offset=offset, span=span)
    outfile.write(header.serialize(packets))

    # Note: The oracle will say True or False, if we should keep a segment
    # And at some point, it will keep saying False forever
    # In other word, the generator never terminate

    # Stream the remainder
    LOG.info('Streaming the remainder of the file')
    chunk_size = SEGMENT_SIZE + CIPHER_DIFF # chunk = cipher segment
    while True:
        segment = infile.read(chunk_size)
        if not segment:
            break
        keep_segment = next(segment_oracle)
        LOG.debug('Keep segment: %s', keep_segment)
        if keep_segment:
            outfile.write(segment)

    del segment_oracle # enough to terminate and remove it?
    LOG.info('Rearrangement Successful')

