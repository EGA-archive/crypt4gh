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
from cryptography.exceptions import InvalidTag

from . import convert_error, close_on_broken_pipe
from . import header

LOG = logging.getLogger(__name__)

SEGMENT_SIZE = 65536
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
    #LOG.debug("Segment: %s..%s", data[:30], data[-30:])

    nonce = os.urandom(12)
    encrypted_data = cipher.encrypt(nonce, data, None)  # No add
    process(nonce) # after producing the segment, so we don't start outputing when an error occurs
    process(encrypted_data)


# The encryption will not produce an edit list packet.
# It'll fast-forward the file to the given position and only encrypt until the end_coodinate or the EOF
def encrypt(keys, infile, outfile, start_coordinate=0, end_coordinate=None):
    '''Encrypt infile into outfile, using the list of keys.'''

    LOG.info('Encrypting the file')


    # Forward to start position
    LOG.debug("  Start Coordinate: %s", start_coordinate)
    try:
        start_coordinate = int(start_coordinate)
        if start_coordinate < 0:
            start_coordinate = 0
            LOG.error('Invalid start coordinate. Using 0 instead')
    except Exception as e:
        LOG.error("Conversion error: %s", e)
        start_coordinate = 0

    if start_coordinate:
        LOG.info("Forwarding to position: %s", start_coordinate)
        infile.seek(start_coordinate, io.SEEK_SET)

    # Where to stop
    if (end_coordinate is not None
        and not isinstance(end_coordinate, int)
        and end_coordinate > start_coordinate):
        LOG.error("    End Coordinate: %s | Converting to None", end_coordinate)
        end_coordinate = None
    max_length = end_coordinate - start_coordinate if end_coordinate else None

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
    # Boy... I buffer a whole segment!
    # TODO: Use a smaller buffer (Requires code rewrite)
    segment = bytearray(SEGMENT_SIZE)

    while True:

        segment_len = infile.readinto(segment)

        if max_length and max_length <= segment_len: # stop early
            segment_len = max_length
            break

        if segment_len < SEGMENT_SIZE: # not a full segment
            break

        data = bytes(segment) # this is a full segment
        _encrypt_segment(data, outfile.write, cipher)
        if max_length:
            max_length -= segment_len
    
    # We reached the last segment and the max_length
    if segment_len > 0:
        data = bytes(segment[:segment_len]) # to discard the bytes from the previous segments
        _encrypt_segment(data, outfile.write, cipher)

    LOG.info('Encryption Successful')


##############################################################
##
##    Symmetric decryption - Chacha20_Poly1305
##
##############################################################

def _cipher_box(f, ciphers):
    CIPHER_SEGMENT_SIZE = SEGMENT_SIZE + CIPHER_DIFF
    while True:
        ciphersegment = f.read(CIPHER_SEGMENT_SIZE)
        ciphersegment_len = len(ciphersegment)
        if ciphersegment_len == 0: 
            # We were at the last segment. Exits the loop
            break
        # Otherwise, decrypt
        assert( ciphersegment_len > CIPHER_DIFF )
        nonce = ciphersegment[:12]
        data = ciphersegment[12:]
        # Trying the different session keys (via the cipher objects)
        # Note: we could order them and if one fails, we move it at the end of the list
        # So... LRU solution. For now, try them as they come.
        for cipher in ciphers:
            try:
                yield cipher.decrypt(nonce, data, None)  # No aad
                break # only break the forloop
            except InvalidTag as tag:
                LOG.error('Decryption failed: %s', tag)
        else: # no cipher worked: Bark!
            raise ValueError('Could not decrypt that block')


# The optional process_output allows us to decrypt and:
# - dump the output to a file
# - not process the output (only checksum it internally)
# - send it (in mem) to another quality control pass

@convert_error
def body_decrypt(ciphers, edits, infile, process_output=None, start_coordinate=0, end_coordinate=None):
    '''Decrypting the data section and verifying its checksum'''

    LOG.debug("  Start Coordinate: %s", start_coordinate)
    LOG.debug("    End Coordinate: %s", end_coordinate)

    assert( isinstance(start_coordinate, int) and (end_coordinate is None or isinstance(end_coordinate, int)) )

    has_range = (start_coordinate != 0 or
                 end_coordinate is not None)
    
    LOG.info("Decrypting content")

    # Dealing with the range
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

    # Decryption
    do_process = callable(process_output)
    for i, segment in enumerate(_cipher_box(infile, ciphers)):
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
def decrypt(keys, infile, outfile, start_coordinate=0, end_coordinate=None):
    '''Decrypt infile into outfile, using a given set of keys.

    If sender_pubkey is specified, it verifies the provenance of the header
    '''
    LOG.info('Decrypting file')
    header_packets = header.parse(infile)
    packets, _ = header.decrypt(header_packets, keys)

    if not packets: # no packets were decrypted
        raise ValueError('No supported encryption method')

    data_packets, edit_packet = header.partition_packets(packets)
    # Parse returns the session key (since it should be method 0) 
    ciphers = [ChaCha20Poly1305(header.parse_enc_packet(packet)) for packet in data_packets]
    edits = header.parse_edit_list_packet(edit_packet) if edit_packet else None

    return body_decrypt(ciphers, edits,
                        infile,
                        process_output=outfile.write,
                        start_coordinate=start_coordinate,
                        end_coordinate=end_coordinate)


##############################################################
##
##    Just reencryption of the header
##
##############################################################


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

