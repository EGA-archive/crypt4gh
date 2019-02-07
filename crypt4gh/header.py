# -*- coding: utf-8 -*-
"""Generate and parse a Crypt4GH header."""

import os
import logging

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
#from nacl.bindings import crypto_box_beforenm as derive_shared_key
from nacl.bindings import crypto_scalarmult as derive_shared_key

from . import __version__
from .keys import retrieve_pubkey

LOG = logging.getLogger(__name__)

MAGIC_NUMBER = b'crypt4gh'

def serialize(header_data):
    '''Serializes a header to a byte stream'''
    header_len = len(header_data)
    LOG.debug('Serializing the header (length: %d)', header_len)
    LOG.debug('Header data: %s', header_data.hex())
    return (MAGIC_NUMBER +
            __version__.to_bytes(4,'little') +
            header_len.to_bytes(4,'little') +
            header_data)

def parse(stream):
    '''Parses a given stream, verifies it and returns header's encrypted part'''

    buf = bytearray(16)
    if stream.readinto(buf) != 16:
        raise ValueError('Header too small')

    # Magic number, 8 bytes
    magic_number = bytes(buf[:8]) # 8 bytes
    if magic_number != MAGIC_NUMBER:
        raise ValueError('Not a CRYPT4GH formatted file')

    # Version, 4 bytes
    version = int.from_bytes(bytes(buf[8:12]), byteorder='little')
    if version != __version__: # only version 1, so far
        raise ValueError('Unsupported CRYPT4GH version')

    # Header length
    header_len = int.from_bytes(bytes(buf[12:16]), byteorder='little')
    LOG.debug('header length: %d', header_len)
    header_data = stream.read(header_len)
    LOG.debug('header data: %s', header_data.hex())
    if len(header_data) < header_len:
        raise ValueError('Header too small')

    return header_data

# Header Encryption Methods Conventions
# -------------------------------------
#
# 0: chacha20_ietf_poly1305
# 1: AES-256-GCM ?
# else: NotImplemented / NotSupported


def encrypt_X25519_Chacha20_Poly1305(algorithm_data, seckey, recipient_pubkey, encryption_method=0):
    '''Computes the encrypted part'''
    data = (encryption_method.to_bytes(4,'little')   +  # 4 bytes
            algorithm_data)                             # See method data size

    pubkey = bytes(retrieve_pubkey(seckey))

    #LOG.debug('Original data: %s', data.hex())
    LOG.debug("         Session Key: %s", algorithm_data.hex())
    LOG.debug('       my public key: %s', pubkey.hex())
    LOG.debug('       my secret key: %s', seckey.hex())
    LOG.debug('recipient public key: %s', recipient_pubkey.hex())

    header_encryption_method = 0

    # X25519 shared key
    shared_key = derive_shared_key(recipient_pubkey, seckey)
    LOG.debug('shared key: %s', shared_key.hex())

    # Chacha20_Poly1305
    engine = ChaCha20Poly1305(shared_key)
    nonce = os.urandom(12)
    header_data = (header_encryption_method.to_bytes(4,'little') +
                   pubkey +
                   nonce +
                   engine.encrypt(nonce, data, None))  # No add
    
    return serialize(header_data)

def encrypt(algorithm_data, seckey, recipient_pubkey, encryption_method=0, header_encryption_method=0):
    '''Computes the encrypted part'''
    if header_encryption_method == 0:
        return encrypt_X25519_Chacha20_Poly1305(algorithm_data,
                                                seckey,
                                                recipient_pubkey,
                                                encryption_method=encryption_method)
    if method == 1:
        raise NotImplementedError('AES-256-GCM support is not implemented')
    raise ValueError('Unsupported Header Encryption Method')


def decrypt_X25519_Chacha20_Poly1305(encrypted_part, privkey, sender_pubkey=None):
    #LOG.debug('  Encrypted data: %s', encrypted_part.hex())
    LOG.debug('    my secret key: %s', privkey.hex())
    LOG.debug('Sender public key: %s', sender_pubkey.hex() if sender_pubkey else None)

    peer_pubkey = encrypted_part[:32]
    if sender_pubkey and sender_pubkey != peer_pubkey:
        raise ValueError("Invalid Peer's Public Key")

    nonce = encrypted_part[32:44]
    algorithm_data = encrypted_part[44:]

    LOG.debug('   peer pubkey: %s', peer_pubkey.hex())
    LOG.debug('         nonce: %s', nonce.hex())
    LOG.debug('encrypted data: %s', algorithm_data.hex())

    if len(algorithm_data) != 52: # 4+32 + tag
        raise ValueError('Invalid encrypted data length')

    # X25519 shared key
    shared_key = derive_shared_key(peer_pubkey, privkey)
    LOG.debug('shared key: %s', shared_key.hex())

    # Chacha20_Poly1305
    engine = ChaCha20Poly1305(shared_key)
    data = engine.decrypt(nonce, algorithm_data, None)  # No add

    #LOG.debug('Original data: %s', data.hex())
    if len(data) != 36: # 4+32
        raise ValueError('Invalid encrypted header part length')
    method = int.from_bytes(data[:4], byteorder='little')             # 4 bytes

    return (method, data[4:])

def decrypt(data, privkey, sender_pubkey=None):
    header_encryption_method = int.from_bytes(data[:4], byteorder='little')
    LOG.debug('Header Encryption Method: %d', header_encryption_method)
    if header_encryption_method == 0:
        return decrypt_X25519_Chacha20_Poly1305(data[4:], privkey, sender_pubkey=sender_pubkey)
    if header_encryption_method == 1:
        raise NotImplementedError('AES-256-GCM support is not implemented')
    raise ValueError(f'Unsupported Header Encryption Method: {header_encryption_method}')

def reencrypt(encrypted_part, privkey, recipient_pubkey, sender_pubkey=None):
    '''Re-encrypt the given header'''
    LOG.info(f'Reencrypting the header')
    method, algorithm_data = decrypt(encrypted_part, sender_pubkey=sender_pubkey)
    # New header
    return encrypt(algorithm_data, privkey, recipient_pubkey, encryption_method=method)
