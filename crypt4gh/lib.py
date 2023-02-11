# -*- coding: utf-8 -*-
"""Handle the encryption of the application data."""

import os
import logging
import io
import collections
from itertools import chain

from nacl.bindings import (crypto_aead_chacha20poly1305_ietf_encrypt,
                           crypto_aead_chacha20poly1305_ietf_decrypt)
from nacl.exceptions import CryptoError


from . import SEGMENT_SIZE
from .exceptions import close_on_broken_pipe
from . import header

LOG = logging.getLogger(__name__)

CIPHER_DIFF = 28
CIPHER_SEGMENT_SIZE = SEGMENT_SIZE + CIPHER_DIFF

# Encryption Methods Conventions
# ------------------------------
#
# 0: chacha20_ietf_poly1305
# 1: AES-256-CTR => Not Implemented
# else: NotSupported

def bitwise_add_one(a):
    b = 1
    while b != 0:
        carry = a & b  # Carry value is calculated 
        a = a ^ b      # Sum value is calculated and stored in a
        b = carry << 1 # The carry value is shifted towards left by a bit
    return a & 0xFFFFFFFF

##############################################################
##
##    Symmetric encryption - Chacha20_Poly1305
##
##############################################################

def _encrypt_segment(data, process, key, aad):
    '''Utility function to generate a nonce, encrypt data with Chacha20, and authenticate it with Poly1305.'''

    #LOG.debug("Segment [%d bytes]: %s..%s", len(data), data[:10], data[-10:])

    nonce = os.urandom(12)
    encrypted_data = crypto_aead_chacha20poly1305_ietf_encrypt(data, aad, nonce, key)
    process(nonce) # after producing the segment, so we don't start outputing when an error occurs
    process(encrypted_data)


@close_on_broken_pipe
def encrypt(keys, infile, outfile):
    '''Encrypt infile into outfile, using the list of keys.


    It fast-forwards to `offset` and encrypts until
    a total of `span` bytes is reached (or to EOF if `span` is None)

    This produces a Crypt4GH file without edit list.
    '''

    LOG.info('Encrypting the file')

    # Preparing the encryption engine
    encryption_method = 0 # only choice for this version
    session_key = os.urandom(32) # we use one session key for all blocks
    aad_seq = os.urandom(4)

    # Output the header
    LOG.debug('Creating Crypt4GH header')
    header_session_key_packets = header.encrypt(header.make_packet_data_enc(encryption_method, session_key),
                                                keys)
    header_sequence_number_packets = header.encrypt(header.make_packet_sequence_number(aad_seq),
                                                    keys)
    header_packets = chain(header_session_key_packets,header_sequence_number_packets)
    header_bytes = header.serialize(header_packets)

    LOG.debug(f'sequence number: %s', header.sequence_number_to_binstr(aad_seq))
    LOG.debug('header length: %d', len(header_bytes))
    outfile.write(header_bytes)

    # ...and cue music
    LOG.debug("Streaming content")
    # oh boy... I buffer a whole segment!
    # TODO: Use a smaller buffer (Requires code rewrite)
    segment = bytearray(SEGMENT_SIZE)

    while True:
        segment_len = infile.readinto(segment)

        LOG.debug('aad_seq: %s', header.sequence_number_to_binstr(aad_seq))

        if segment_len == 0: # We end up on a segment boundary: we encrypt an extra empty (final) segment
            _encrypt_segment(b'', outfile.write, session_key, aad_seq)
            break

        if segment_len < SEGMENT_SIZE: # not a full segment
            data = bytes(segment[:segment_len]) # to discard the bytes from the previous segments
            _encrypt_segment(data, outfile.write, session_key, aad_seq)
            break

        data = bytes(segment) # this is a full segment
        _encrypt_segment(data, outfile.write, session_key, aad_seq)

        # update the sequence number
        aad_seq = bitwise_add_one(aad_seq) # can and should wrap around
        

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

class ProcessingOver(Exception):
    pass

def decrypt_block(ciphersegment, session_keys, aad):
    # Trying the different session keys (via the cipher objects)
    # Note: we could order them and if one fails, we move it at the end of the list
    # So... LRU solution. For now, try them as they come.
    nonce = ciphersegment[:12]
    data = ciphersegment[12:]

    for key in session_keys:
        try:
            return crypto_aead_chacha20poly1305_ietf_decrypt(data, aad, nonce, key)
        except CryptoError as tag:
            LOG.error('Decryption failed: %s', tag)
    else: # no cipher worked: Bark!
        raise ValueError('Could not decrypt that block')


def limited_output(offset=0, limit=None, process=None):
    '''Generator that receives clear text and does not process more than limit bytes (if limit is not None).

    Raises ProcessingOver if the limit is reached'''

    LOG.debug('Slicing from %s | Keeping %s bytes', offset, 'all' if limit is None else limit)

    if not callable(process):
        raise ValueError('process_output is not callable')

    assert( 
        (isinstance(offset, int) and offset >= 0)
        and
        (limit is None
         or
         (isinstance(limit, int) and limit > 0))
    )

    while True:
        data = yield
        data_len = len(data)

        if data_len == 0: # That's the final empty segment
            raise ProcessingOver()

        if data_len < offset: # not enough data to chop off
            offset -= data_len
            continue # ignore output

        if limit is None:
            process(data[offset:])  # no copying here if offset=0!
        else:

            if limit < (data_len - offset): # should stop early
                process(data[offset:limit+offset])
                raise ProcessingOver()
            else:
                process(data[offset:])  # no copying here if offset=0!
                limit -= (data_len - offset)

        offset = 0 # reset offset


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
    session_keys, aead_seq = header.deconstruct(infile, keys, sender_pubkey=sender_pubkey)

    # Infile in now positioned at the beginning of the data portion

    # Generator to slice the output
    output = limited_output(offset=offset, limit=span, process=outfile.write)
    next(output) # start it

    # In this case, we try to fast-forward, and adjust the offset
    if offset >= SEGMENT_SIZE: 
        start_segment, offset = divmod(offset, SEGMENT_SIZE)
        LOG.warning('Fast-forwarding %d segments', start_segment)
        start_ciphersegment = start_segment * CIPHER_SEGMENT_SIZE
        infile.seek(start_ciphersegment, io.SEEK_CUR)  # move forward

        # adjust the sequence number of the start segment
        for _ in range(start_segment): # todo: add the number directly instead of 1 by 1
            aead_seq = bitwise_add_one(aead_seq)

    # Decrypt all segments until the end
    LOG.debug('aad: %s', header.sequence_number_to_binstr(aad))
    try:
        for ciphersegment in cipher_chunker(infile, CIPHER_SEGMENT_SIZE):
            segment = decrypt_block(ciphersegment, session_keys, aead_seq)
            output.send(segment)
            aead_seq = bitwise_add_one(aead_seq)
            LOG.debug('aad: %s', header.sequence_number_to_binstr(aead_seq))
    except ProcessingOver:  # output raised it
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
