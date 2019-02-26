# -*- coding: utf-8 -*-

'''This module implements the public/private key format for Crypt4GH.'''

import os
import io
import logging
from base64 import b64decode, b64encode
from hashlib import pbkdf2_hmac
import bcrypt
try:
    from hashlib import scrypt
    with_scrypt = True
except:
    #import sys
    #print('Warning: No support for scrypt', file=sys.stderr)
    with_scrypt = False

from nacl.public import PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import exit_on_invalid_passphrase

LOG = logging.getLogger(__name__)

MAGIC_WORD = b'c4gh-v1'

#######################################################################
## Encoded strings
#######################################################################
def _encode_string(s):
    return len(s).to_bytes(2,'big') + s

def _decode_string(stream):
    slen = int.from_bytes(stream.read(2), byteorder='big')
    data = stream.read(slen)
    if len(data) != slen:
        raise ValueError("Invalid format: No enough data")
    return data

#######################################################################
## Key Derivation
#######################################################################

def _derive_key(alg, passphrase, salt, rounds):
    if alg == b'scrypt':
        return scrypt(passphrase, salt, 1<<14, 8, 1, dklen=32)
    if alg == b'bcrypt':
        return bcrypt.kdf(passphrase, salt=salt, desired_key_bytes=32, rounds=rounds)
    if alg == b'pbkdf2_hmac_sha256':
        return pbkdf2_hmac('sha256', passphrase, salt, rounds, dklen=32)
    raise NotImplementedError(f'Unsupported KDF: {alg}')

def retrieve_pubkey(private_key):
    '''Get public key from private key'''
    return PrivateKey(private_key).public_key

#######################################################################
## Encoding
#######################################################################
# Ideally, scrypt is chosen over bcrypt or pbkdf2_hmac_sha256
# But in case there is no support for it, we pick bcrypt
_KDFS = {
    b'scrypt': (16, None),
    b'bcrypt': (16, 100),
    b'pbkdf2_hmac_sha256': (16, 100000),
}

def _encode_encrypted_private_key(key, passphrase, comment, rounds):
    global _KDFS, with_scrypt
    kdfname = b'scrypt' if with_scrypt else b'bcrypt'
    saltsize, rounds = _KDFS[kdfname]
    salt = os.urandom(saltsize)
    derived_key = _derive_key(kdfname, passphrase, salt, rounds)
    nonce = os.urandom(12)
    key_bytes = bytes(key)  # Uses RawEncoder
    encrypted_key = ChaCha20Poly1305(derived_key).encrypt(nonce, key_bytes, None)  # No add

    LOG.debug('Derived Key: %s', derived_key.hex().upper())
    LOG.debug('      Nonce: %s', nonce.hex().upper())
    
    return (MAGIC_WORD + 
	    _encode_string(kdfname) +
            _encode_string(rounds.to_bytes(4,'big') + salt) +
	    _encode_string(b'chacha20_poly1305') + 
	    _encode_string(nonce + encrypted_key) + 
	    (_encode_string(comment) if comment is not None else b''))


def generate(seckey, pubkey, callback=None, comment=None, rounds=100):
    '''Generate a keypair.'''

    # Generate the keys
    sk = PrivateKey.generate()
    LOG.debug('Private Key: %s', bytes(sk).hex().upper())

    with open(pubkey, 'bw') as f:
        f.write(b'-----BEGIN CRYPT4GH PUBLIC KEY-----\n')
        pkey = bytes(sk.public_key)
        LOG.debug('Public Key: %s', pkey.hex().upper())
        f.write(b64encode(pkey))
        f.write(b'\n-----END CRYPT4GH PUBLIC KEY-----\n')

    with open(seckey, 'bw') as f:
        is_encrypted = False
        if callback:
            is_encrypted = True
            passphrase = callback()
            pkey = _encode_encrypted_private_key(sk, passphrase.encode(), comment, rounds)
            LOG.debug('Encoded Private Key: %s', pkey.hex().upper())
        else:
            import sys
            LOG.warning(f'WARNING: The private key {seckey} is not encrypted', file=sys.stderr)
            pkey = bytes(sk)
            LOG.debug('Non-Encrypted Private Key: %s', pkey.hex().upper())

        f.write(b'-----BEGIN ')
        if is_encrypted:
            f.write(b'ENCRYPTED ')
        f.write(b'PRIVATE KEY-----\n')
        f.write(b64encode(pkey))
        f.write(b'\n-----END ')
        if is_encrypted:
            f.write(b'ENCRYPTED ')
        f.write(b'PRIVATE KEY-----\n')


#######################################################################
## Decoding
#######################################################################

@exit_on_invalid_passphrase
def _parse_encrypted_key(stream, callback):

    if MAGIC_WORD != stream.read(len(MAGIC_WORD)):
        raise ValueError('Invalid key format')

    kdfname = _decode_string(stream)
    kdfoptions = _decode_string(stream)
    rounds = int.from_bytes(kdfoptions[:4], byteorder='big')
    salt = kdfoptions[4:]

    LOG.debug("Encrypted with %s [rounds: %d]", kdfname, rounds)

    ciphername = _decode_string(stream)
    if ciphername != b'chacha20_poly1305':
        raise NotImplementedError(f'Unsupported Cipher: {ciphername}')

    assert( callback and callable(callback) )
    passphrase = callback()
    shared_key = _derive_key(kdfname, passphrase.encode(), salt, rounds)
    LOG.debug('Shared Key: %s', shared_key.hex().upper())
    private_data = _decode_string(stream)
    nonce = private_data[:12]
    encrypted_data = private_data[12:]
    return ChaCha20Poly1305(shared_key).decrypt(nonce, encrypted_data, None)  # No add

def _load(keyfile):
    with open(keyfile, 'rb') as f:
        lines = f.readlines()
        is_encrypted = (b'ENCRYPTED' in lines[0])
        return is_encrypted, b64decode(b''.join(lines[1:-1]))

def get_public_key(keyfile):
    '''Read the public key from keyfile location.'''
    is_encrypted, data = _load(keyfile)
    assert( not is_encrypted )
    return data

def get_private_key(keyfile, callback):
    '''Read the private key from keyfile location.

    If the private key is encrypted, the user will be prompted for the passphrase.
    '''
    is_encrypted, data = _load(keyfile)
    if is_encrypted:
        return _parse_encrypted_key(io.BytesIO(data), callback)
    return data


