import logging
import os
import sys
from base64 import b64encode

from nacl.public import PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .kdf import derive_key, get_kdf, scrypt_supported, KDFS
from ..exceptions import exit_on_invalid_passphrase

LOG = logging.getLogger(__name__)

MAGIC_WORD = b'c4gh-v1'

#######################################################################
## Encoded strings
#######################################################################
def encode_string(s):
    if s is None:
        s = b'none'
    return len(s).to_bytes(2,'big') + s

def decode_string(stream):
    slen = int.from_bytes(stream.read(2), byteorder='big')
    data = stream.read(slen)
    if len(data) != slen:
        raise ValueError("Invalid format: No enough data")
    return data


def encode_private_key(key, passphrase, comment):
    if not passphrase:  # None and empty
        print(f'WARNING: The private key is not encrypted', file=sys.stderr)
        return (MAGIC_WORD + 
	        encode_string(None) + # kdf = none (no kdfoptions)
	        encode_string(None) + # cipher = none
	        encode_string(bytes(key)) + # clear key material
	        (encode_string(comment) if comment is not None else b'')) # optional comment

    # We have a passphrase: we encrypt the private key
    # Ideally, scrypt is chosen over bcrypt or pbkdf2_hmac_sha256
    # But in case there is no support for it, we pick bcrypt
    kdfname = b'scrypt' if scrypt_supported else b'bcrypt'
    saltsize, rounds = get_kdf(kdfname)
    salt = os.urandom(saltsize)
    derived_key = derive_key(kdfname, passphrase, salt, rounds) # dklen = 32
    nonce = os.urandom(12)
    key_bytes = bytes(key)  # Uses RawEncoder
    encrypted_key = ChaCha20Poly1305(derived_key).encrypt(nonce, key_bytes, None)  # No add

    LOG.debug('Derived Key: %s', derived_key.hex().upper())
    LOG.debug('      Nonce: %s', nonce.hex().upper())
    
    return (MAGIC_WORD + 
	    encode_string(kdfname) + # kdf
            encode_string(rounds.to_bytes(4,'big') + salt) + # kdf options
	    encode_string(b'chacha20_poly1305') +  # cipher
	    encode_string(nonce + encrypted_key) +  # encrypted key material
	    (encode_string(comment) if comment is not None else b'')) # optional comment


def generate(seckey, pubkey, callback=None, comment=None):
    '''Generate a keypair.'''

    # Generate the keys
    sk = PrivateKey.generate()
    LOG.debug('Private Key: %s', bytes(sk).hex().upper())

    os.umask(0o222) # Restrict to r-- r-- r--

    with open(pubkey, 'bw', ) as f:
        f.write(b'-----BEGIN CRYPT4GH PUBLIC KEY-----\n')
        pkey = bytes(sk.public_key)
        LOG.debug('Public Key: %s', pkey.hex().upper())
        f.write(b64encode(pkey))
        f.write(b'\n-----END CRYPT4GH PUBLIC KEY-----\n')

    os.umask(0o277) # Restrict to r-- --- ---

    with open(seckey, 'bw') as f:
        passphrase = callback().encode() if callback else None
        pkey = encode_private_key(sk, passphrase, comment)
        LOG.debug('Encoded Private Key: %s', pkey.hex().upper())

        f.write(b'-----BEGIN CRYPT4GH PRIVATE KEY-----\n')
        f.write(b64encode(pkey))
        f.write(b'\n-----END CRYPT4GH PRIVATE KEY-----\n')


#######################################################################
## Decoding
#######################################################################

@exit_on_invalid_passphrase
def parse_private_key(stream, callback):

    kdfname = decode_string(stream)
    LOG.info("KDF: %s", kdfname)

    if kdfname != b'none' and kdfname not in KDFS:
        raise ValueError("Invalid Crypt4GH Key format")

    if kdfname != b'none':
        kdfoptions = decode_string(stream)
        rounds = int.from_bytes(kdfoptions[:4], byteorder='big')
        salt = kdfoptions[4:]
        LOG.debug("Salt: %s", salt.hex().upper())
        LOG.debug("Rounds: %d", rounds)
    else:
        LOG.debug("Not Encrypted")

    ciphername = decode_string(stream)
    LOG.info("Ciphername: %s", ciphername)

    private_data = decode_string(stream)

    if ciphername == b'none':
        return private_data # ignore the comment

    # Else, the data was encrypted
    if ciphername != b'chacha20_poly1305':
        raise ValueError(f"Invalid Crypt4GH Key format (Unsupported Cipher: {ciphername})")

    assert( callback and callable(callback) )
    passphrase = callback().encode()
    shared_key = derive_key(kdfname, passphrase, salt, rounds) # dklen = 32
    LOG.debug('Shared Key: %s', shared_key.hex().upper())
    nonce = private_data[:12]
    LOG.debug('Nonce: %s', nonce.hex().upper())
    encrypted_data = private_data[12:]
    return ChaCha20Poly1305(shared_key).decrypt(nonce, encrypted_data, None)  # No add

