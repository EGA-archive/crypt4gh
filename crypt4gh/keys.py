# -*- coding: utf-8 -*-

'''
This module implements the public/private key format for Crypt4GH.

1. Overall format

The key consists of a preamble, the public key and an encrypted matching private key.

#define MAGIC_WORD      "crypt4gh"

        byte[]	MAGIC_WORD
	string	kdfname                                     [here: pbkdf2_hmac_sha256, or bcrypt]
	string  (rounds || salt)                            [here: rounds is a 4 big-endian bytes]
	string	ciphername                                  [here: chacha20_poly1305]
	string	nonce (12 bytes) || encrypted private key
	string	comment                                     [optional]

Note: Everything "string" consists of a length n (encoded as 2 big-endian bytes) and a sequence of n bytes

2. Encryption

The KDF is used to derive a secret key from a user-supplied passphrase.
A nonce is randomly generated, and used in conjonction with the secret key to encrypt the private key.
The cipher is here Chacha20_Poly1305.

3. No encryption

In case both the ciphername is "none" and the KDF is "none", 
are used with empty passphrases. The options if the KDF "none"
are the empty string.

4. Final output

We encode the above data in Base64 and outputs the result with the following markers

-----BEGIN CRYPT4GH PRIVATE KEY-----
BASE64 ENCODED DATA
-----END CRYPT4GH PRIVATE KEY-----

For the public key
-----BEGIN CRYPT4GH PUBLIC KEY-----
BASE64 ENCODED DATA
-----END CRYPT4GH PUBLIC KEY-----

'''

import os
import io
import logging
from base64 import b64decode, b64encode
#from hashlib import pbkdf2_hmac
import bcrypt

from nacl.public import PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

LOG = logging.getLogger(__name__)

MAGIC_WORD = b'crypt4gh'

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
    if alg == b'bcrypt':
        return bcrypt.kdf(passphrase, salt=salt, desired_key_bytes=32, rounds=rounds)
    if alg == b'pbkdf2_hmac_sha256':
        return pbkdf2_hmac('sha256', passphrase, salt, rounds, dklen=32)
    raise NotImplementedError(f'Unsupported KDF: {alg}')

def retrieve_pubkey(private_key):
    return PrivateKey(private_key).public_key

#######################################################################
## Encoding
#######################################################################
# I choose bcrypt or pbkdf2_hmac_sha256

def _encode_encrypted_private_key(key, passphrase, comment, rounds):
    kdfname = b'bcrypt'     # b'pbkdf2_hmac_sha256'
    salt = os.urandom(16)   # os.urandom(16)
    rounds = rounds or 100  # 100000
    shared_key = _derive_key(kdfname, passphrase, salt, rounds)
    nonce = os.urandom(12)
    key_bytes = bytes(key)  # Uses RawEncoder
    encrypted_key = ChaCha20Poly1305(shared_key).encrypt(nonce, key_bytes, None)  # No add

    LOG.debug('Shared Key: %s', shared_key.hex().upper())
    
    return (MAGIC_WORD + 
	    _encode_string(kdfname) +
            _encode_string(rounds.to_bytes(4,'big') + salt) +
	    _encode_string(b'chacha20_poly1305') + 
	    _encode_string(nonce + encrypted_key) + 
	    (_encode_string(comment) if comment is not None else b''))

def _encode_unencrypted_private_key(key, comment):
    return (MAGIC_WORD + 
	    _encode_string(b'none') +
	    _encode_string(b'none') + 
	    _encode_string(bytes(key)) + # Uses the RawEncoder 
	    (_encode_string(comment) if comment is not None else b''))


def generate_ec(seckey, pubkey, callback=None, comment=None, rounds=100):

    # Generate the keys
    sk = PrivateKey.generate()
    LOG.debug('Private Key: %s', bytes(sk).hex().upper())

    with open(pubkey, 'bw') as f:
        f.write(b'-----BEGIN CRYPT4GH PUBLIC KEY-----\n')
        pkey = bytes(sk.public_key)
        LOG.debug('Public Key: %s', pkey.hex().upper())
        f.write(b64encode(pkey))
        f.write(b'\n-----END CRYPT4GH PUBLIC KEY-----')

    with open(seckey, 'bw') as f:
        f.write(b'-----BEGIN PRIVATE KEY-----\n')
        if callback:
            passphrase = callback()
            pkey = _encode_encrypted_private_key(sk, passphrase.encode(), comment, rounds)
        else:
            pkey = _encode_unencrypted_private_key(sk, comment)
        LOG.debug('Encoded Private Key: %s', pkey.hex().upper())
        f.write(b64encode(pkey))
        f.write(b'\n-----END PRIVATE KEY-----')


#######################################################################
## Decoding
#######################################################################


def load(keyfile):
    with open(keyfile, 'rb') as f:
        return b64decode(b''.join(f.readlines()[1:-1]))

def get_public_key(keyfile):
    return load(keyfile)

def get_private_key(keyfile, callback):
    stream = io.BytesIO(load(keyfile))
    if MAGIC_WORD != stream.read(8):
        raise ValueError('Invalid key format')

    kdfname = _decode_string(stream)
    if kdfname == b'none':
        ciphername = _decode_string(stream)
        assert( ciphername == b'none' )
        LOG.debug("Not encrypted")
        return _decode_string(stream)

    # We have an encrypted private key
    kdfoptions = _decode_string(stream)
    rounds = int.from_bytes(kdfoptions[:4], byteorder='big')
    salt = kdfoptions[4:]

    LOG.debug("Encrypted with %s [rounds: %d]", kdfname, rounds)

    ciphername = _decode_string(stream)
    if ciphername != b'chacha20_poly1305':
        raise NotImplementedError(f'Unsupported Cipher: {ciphername}')

    assert( callback )
    passphrase = callback()
    shared_key = _derive_key(kdfname, passphrase.encode(), salt, rounds)
    LOG.debug('Shared Key: %s', shared_key.hex().upper())
    private_data = _decode_string(stream)
    nonce = private_data[:12]
    encrypted_data = private_data[12:]
    return ChaCha20Poly1305(shared_key).decrypt(nonce, encrypted_data, None)  # No add
