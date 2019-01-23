# -*- coding: utf-8 -*-
"""Handle the encryption of the application data.

It encrypts or decrypts a given file read from stdin, and outputs the result to stdout.

It also reencrypts Crypt4GH-formatted input, into another Crypt4GH-formatted output.
"""

import os
import logging
import hashlib
from hmac import compare_digest
import io

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import convert_error, close_on_broken_pipe
from .header import (parse as header_parse,
                     encrypt as header_encrypt,
                     decrypt as header_decrypt,
                     reencrypt as header_reencrypt)

LOG = logging.getLogger(__name__)

SEGMENT_SIZE = 65536
CIPHER_DIFF = 28

# Encryption Methods Conventions
# ------------------------------
#
# 0: chacha20_ietf_poly1305
# 1: AES-256-CTR => Not Implemented
# else: NotSupported

def _raise_if_not_supported_method(method):
    if method == 0:
        return
    if method == 1:
        raise NotImplementedError('AES support is not implemented')
    raise ValueError('Unsupported encryption method')


##############################################################
##
##    Symmetric encryption - Chacha20_Poly1305
##
##############################################################

def _encrypt_segment(data, outfile, session_key):
    '''Utility function to generate a nonce, encrypt data with Chacha20, and authenticate it with Poly1305.'''
    #LOG.debug("Segment: %s..%s", data[:30], data[-30:])

    cipher = ChaCha20Poly1305(session_key)
    nonce = os.urandom(12)
    encrypted_data = cipher.encrypt(nonce, data, None)  # No add
    outfile.write(nonce)
    outfile.write(encrypted_data)

def encrypt(seckey, recipient_pubkey, infile, outfile):
    '''Encrypt infile into outfile, using seckey and recipient_pubkey.'''
    LOG.info('Encrypting the file')
    session_key = os.urandom(32)

    LOG.debug('Creating Crypt4GH header')
    header_bytes = header_encrypt(session_key, seckey, recipient_pubkey)
    outfile.write(header_bytes)

    LOG.debug("Streaming content")
    # Boy... I buffer a whole segment!
    # TODO: Use a smaller buffer (Requires code rewrite)
    segment = bytearray(SEGMENT_SIZE)
    segment_len = infile.readinto(segment)
    while segment_len == SEGMENT_SIZE:
        data = bytes(segment)
        _encrypt_segment(data, outfile, session_key)
        segment_len = infile.readinto(segment)

    # We reached the last segment
    data = bytes(segment[:segment_len]) # to discard the bytes from the previous segments
    _encrypt_segment(data, outfile, session_key)

    LOG.info('Encryption Successful')

def _cipher_box(f, cipher):
    CIPHER_SEGMENT_SIZE = SEGMENT_SIZE + CIPHER_DIFF
    while True:
        ciphersegment = f.read(CIPHER_SEGMENT_SIZE)
        ciphersegment_len = len(ciphersegment)
        if ciphersegment_len == 0: 
            # We were at the last segment. Exits the loop
            break
        # Otherwise, decrypt
        assert( ciphersegment_len > CIPHER_DIFF )
        yield cipher.decrypt(ciphersegment[:12], ciphersegment[12:], None)  # No aad


# The optional process_output allows us to decrypt and:
# - dump the output to a file
# - not process the output (only checksum it internally)
# - send it (in mem) to another quality control pass

@convert_error
def body_decrypt(infile, method, session_key, process_output=None, start_coordinate=0, end_coordinate=None):
    '''Decrypting the data section and verifying its checksum'''

    LOG.debug(" Encryption Method: %s", method)
    LOG.debug("       Session Key: %s", session_key.hex())
    LOG.debug("  Start Coordinate: %s", start_coordinate)
    LOG.debug("    End Coordinate: %s", end_coordinate)

    assert( isinstance(start_coordinate, int) and (end_coordinate is None or isinstance(end_coordinate, int)) )

    has_range = (start_coordinate != 0 or
                 end_coordinate is not None)
    
    _raise_if_not_supported_method(method)
    LOG.info("Decrypting content")
    
    cipher = ChaCha20Poly1305(session_key)
    do_process = callable(process_output)

    if has_range:
        start_segment, start_offset = divmod(start_coordinate, SEGMENT_SIZE)
        if start_segment: # not 0
            start_ciphersegment = start_segment * (SEGMENT_SIZE + CIPHER_DIFF)
            infile.seek(start_ciphersegment, io.SEEK_CUR)  # move forward
            
        nb_segments, end_segment, end_offset = None, None, None
        if end_coordinate is not None:
            end_segment, end_offset = divmod(end_coordinate, SEGMENT_SIZE)
            if end_offset == 0:
                end_segment -= 1
                end_offset = SEGMENT_SIZE
            nb_segments = end_segment - start_segment
            if nb_segments == 0:
                end_offset -= start_offset
 
        LOG.debug('Start segment: %d | Offset: %d', start_segment, start_offset)
        LOG.debug('  End segment: %s | Offset: %s', end_segment, end_offset)
        LOG.debug(' # of segment: %s', nb_segments)

    for i, segment in enumerate(_cipher_box(infile, cipher)):
        #LOG.debug("Segment: %s..%s", segment[:30], segment[-30:])
        if has_range and i == 0 and start_offset:
            segment = segment[start_offset:]
        if has_range and i == nb_segments:
            segment = segment[:end_offset]

        if do_process:
            process_output(segment)

        if has_range and i == nb_segments:
            break

    LOG.info('Decryption Successful')

    
@close_on_broken_pipe
def decrypt(seckey, infile, outfile, sender_pubkey=None, start_coordinate=0, end_coordinate=None):
    '''Decrypt infile into outfile, using seckey.

    If sender_pubkey is specified, it verifies the provenance of the header
    '''
    LOG.info('Decrypting file')
    header_data = header_parse(infile)
    #LOG.debug('Header is the header\n %s', header)
    method, session_key = header_decrypt(header_data, seckey, sender_pubkey=sender_pubkey)
    # Decrypt the rest
    return body_decrypt(infile,
                        method,
                        session_key,
                        process_output=outfile.write,
                        start_coordinate=start_coordinate,
                        end_coordinate=end_coordinate)


def reencrypt(seckey, recipient_pubkey, infile, outfile, sender_pubkey=None, chunk_size=4096):
    '''Extract header from infile and generetes another one to outfile. The encrypted data section is only copied from infile to outfile.'''

    header_data = header_parse(infile)
    header = header_reencrypt(header_data, seckey, recipient_pubkey, sender_pubkey=None)
    outfile.write(header)

    LOG.info(f'Streaming the remainer of the file')
    while True:
        data = infile.read(chunk_size)
        if not data:
            break
        outfile.write(data)

    LOG.info('Reencryption Successful')
