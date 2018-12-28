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

# Checksum Algorithms Conventions
# -------------------------------
# 0: None
# 1: md5
# 2: sha256
# else: NotImplemented / NotSupported

def _raise_if_not_supported_checksum(checksum):
    if checksum not in (0,1,2):
        raise ValueError('Unsupported checksum algorithm')

def _get_checksum_algorithm(checksum):
    if checksum == 0:
        return None
    if checksum == 1:
        print("MD5 should not be used", file=sys.stderr)
        return hashlib.md5()
    if checksum == 2:
        return hashlib.sha256()
    raise ValueError('Unsupported checksum algorithm')

DEFAULT_CHECKSUM_ALGORITHM = 2

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

def encrypt(seckey, recipient_pubkey, infile, outfile, checksum_algorithm=DEFAULT_CHECKSUM_ALGORITHM):
    '''Encrypt infile into outfile, using seckey and recipient_pubkey.

    If checksum_algorithm is not 0, the computed checksum value, over infile is appended to the data.
    '''
    LOG.info('Encrypting the file')
    session_key = os.urandom(32)

    LOG.debug('Creating Crypt4GH header')
    header_bytes = header_encrypt(session_key, seckey, recipient_pubkey)
    outfile.write(header_bytes)

    LOG.debug("Preparing the checksum")
    md = _get_checksum_algorithm(checksum_algorithm)

    LOG.debug("Streaming content")
    # Boy... I buffer a whole segment!
    # TODO: Use a smaller buffer (Requires code rewrite)
    segment = bytearray(SEGMENT_SIZE)
    segment_len = infile.readinto(segment)
    while segment_len == SEGMENT_SIZE:
        data = bytes(segment)
        if md:
            md.update(data)
        _encrypt_segment(data, outfile, session_key)
        segment_len = infile.readinto(segment)

    # We reached the last segment
    data = bytes(segment[:segment_len]) # to discard the bytes from the previous segments
    #LOG.info('Last block: %s', data[:30])
    if md:
        md.update(data)
        digest = md.digest()
        LOG.debug('Digest: %s [%d]', digest.hex().upper(), len(digest))
        data += digest

    # Need to cut into 2 segments?
    if len(data) > SEGMENT_SIZE:
        _encrypt_segment(data[:SEGMENT_SIZE], outfile, session_key)
        data = data[SEGMENT_SIZE:]
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
def body_decrypt(infile, checksum_algorithm, method, session_key, process_output=None, start_coordinate=0, end_coordinate=None):
    '''Decrypting the data section and verifying its checksum'''

    LOG.debug("Checksum algorithm: %s", checksum_algorithm)
    LOG.debug(" Encryption Method: %s", method)
    LOG.debug("       Session Key: %s", session_key.hex())
    LOG.debug("  Start Coordinate: %s", start_coordinate)
    LOG.debug("    End Coordinate: %s", end_coordinate)

    assert( isinstance(start_coordinate, int) and (end_coordinate is None or isinstance(end_coordinate, int)) )

    has_range = (start_coordinate != 0 or
               end_coordinate is not None)

    _raise_if_not_supported_method(method)
    LOG.info("Decrypting content")
    
    md = _get_checksum_algorithm(checksum_algorithm)
    LOG.debug("Preparing the checksum: %s", md)

    if md and has_range:
        LOG.debug("Requesting a range: Turning off the message digest")
        md = None

    cipher = ChaCha20Poly1305(session_key)
    do_process = callable(process_output)

    if has_range:
        start_segment, start_offset = divmod(start_coordinate, SEGMENT_SIZE)
        if start_segment: # not 0
            start_ciphersegment = start_segment * (SEGMENT_SIZE + CIPHER_DIFF)
            infile.seek(start_ciphersegment, io.SEEK_CUR)  # move forward

        end_segment, end_offset = divmod(end_coordinate, SEGMENT_SIZE)
        nb_segments = end_segment - start_segment

        LOG.debug('Start segment: %d | Offset: %d', start_segment, start_offset)
        LOG.debug('  End segment: %d | Offset: %d', end_segment, end_offset)
        LOG.debug(' # of segment: %d', nb_segments)

    mdbuf = b''
    for i, segment in enumerate(_cipher_box(infile, cipher)):
        #LOG.debug("Segment: %s..%s", segment[:30], segment[-30:])
        if md:
            # Remember the last bytes of the segment
            segment = mdbuf + segment
            assert( len(segment) >= md.digest_size )
            mdbuf = segment[-md.digest_size:]
            segment = segment[:-md.digest_size]
            assert( len(segment) <= SEGMENT_SIZE )
            md.update(segment)

        if has_range and i == 0:
            segment = segment[start_offset:]
        if has_range and i == nb_segments:
            segment = segment[:end_offset]

        if do_process:
            process_output(segment)

        if has_range and i == nb_segments:
            break

    # Checksum compare (if no range)
    if md:
        assert( len(mdbuf) == md.digest_size )
        digest = mdbuf[-md.digest_size:]
        if not compare_digest(digest, md.digest()):
            LOG.debug('Computed MDC: %s', md.hexdigest().upper())
            LOG.debug('Original MDC: %s', digest.hex().upper())
            raise ValueError('Invalid checksum')
        else:
            LOG.debug('Digest: %s [%d]', digest.hex().upper(), len(digest))

    LOG.info('Decryption Successful')

    
@close_on_broken_pipe
def decrypt(seckey, infile, outfile, sender_pubkey=None, start_coordinate=0, end_coordinate=None):
    '''Decrypt infile into outfile, using seckey.

    If sender_pubkey is specified, it verifies the provenance of the header
    '''
    LOG.info('Decrypting file')
    header_data = header_parse(infile)
    #LOG.debug('Header is the header\n %s', header)
    checksum_algorithm, method, session_key = header_decrypt(header_data, seckey, sender_pubkey=sender_pubkey)
    # Decrypt the rest
    return body_decrypt(infile,
                        checksum_algorithm,
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
