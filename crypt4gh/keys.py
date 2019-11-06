# -*- coding: utf-8 -*-

'''This module implements the public/private key format for Crypt4GH.'''

import sys
import os
import io
import logging
import logging.config
from base64 import b64decode, b64encode
from hashlib import pbkdf2_hmac
#import traceback
from functools import partial
from getpass import getpass
import bcrypt
try:
    from hashlib import scrypt
    scrypt_supported = True
except:
    #import sys
    #print('Warning: No support for scrypt', file=sys.stderr)
    scrypt_supported = False

from nacl.public import PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from docopt import docopt


from . import exit_on_invalid_passphrase
from . import __title__, __version__, PROG

LOG = logging.getLogger(__name__)

DEFAULT_LOG = os.getenv('C4GH_LOG', None)
DEFAULT_PK  = os.getenv('C4GH_PUBLIC_KEY', '~/.c4gh/key.pub')
DEFAULT_SK  = os.getenv('C4GH_SECRET_KEY', '~/.c4gh/key')

MAGIC_WORD = b'c4gh-v1'

__doc__ = f'''
 
Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.

Usage:
   {PROG}-keygen [-hv] [--log <file>] [-f] [--pk <path>] [--sk <path>] [--nocrypt] [-C <comment>]

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <file>           Path to the logger file (in YML format)
   --sk <keyfile>         Curve25519-based Private key [default: {DEFAULT_SK}]
   --pk <keyfile>         Curve25519-based Public key  [default: {DEFAULT_PK}]
   -C <comment>           Key's Comment
   --nocrypt              Do not encrypt the private key.
                          Otherwise it is encrypted in the Crypt4GH key format
   -f                     Overwrite the destination files


Environment variables:
   C4GH_LOG         If defined, it will be used as the default logger
   C4GH_PUBLIC_KEY  If defined, it will be used as the default public key (ie --pk ${{C4GH_PUBLIC_KEY}})
   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${{C4GH_SECRET_KEY}})
   C4GH_PASSPHRASE  If defined, it will be used as the passphrase
                    for decoding the secret key, replacing the callback.
                    Note: this is insecure. Only used for testing
 
'''


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


#######################################################################
## Encoding
#######################################################################

_KDFS = {
    b'scrypt': (16, None),
    b'bcrypt': (16, 100),
    b'pbkdf2_hmac_sha256': (16, 100000),
}

def _encode_encrypted_private_key(key, passphrase, comment):
    global _KDFS, scrypt_supported
    # Ideally, scrypt is chosen over bcrypt or pbkdf2_hmac_sha256
    # But in case there is no support for it, we pick bcrypt
    kdfname = b'scrypt' if scrypt_supported else b'bcrypt'
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


def generate(seckey, pubkey, callback=None, comment=None):
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
            pkey = _encode_encrypted_private_key(sk, passphrase.encode(), comment)
            LOG.debug('Encoded Private Key: %s', pkey.hex().upper())
        else:
            import sys
            print(f'WARNING: The private key {seckey} is not encrypted', file=sys.stderr)
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

def _load(filepath):
    with open(filepath, 'rb') as f:
        lines = f.readlines()
        is_encrypted = (b'ENCRYPTED' in lines[0])
        return is_encrypted, b64decode(b''.join(lines[1:-1]))

def get_public_key(filepath):
    '''Read the public key from keyfile location.'''
    is_encrypted, data = _load(filepath)
    assert( not is_encrypted )
    return data

def get_private_key(filepath, callback):
    '''Read the private key from keyfile location.

    If the private key is encrypted, the user will be prompted for the passphrase.
    '''
    is_encrypted, data = _load(filepath)
    if is_encrypted:
        return _parse_encrypted_key(io.BytesIO(data), callback)
    return data


###################
### CLI
###################


def run(argv=sys.argv[1:]):

    # Parse CLI arguments
    version = f'{__title__} (version {__version__})'
    args = docopt(__doc__, argv, help=True, version=version)

    # Logging
    logger = args['--log'] or DEFAULT_LOG
    if logger and os.path.exists(logger):
        with open(logger, 'rt') as stream:
            import yaml
            logging.config.dictConfig(yaml.safe_load(stream))

    # I prefer to clean up
    for s in ['--log', '--help', '--version']:#, 'help', 'version']:
        del args[s]

    # print(args)

    pubkey = os.path.expanduser(args['--pk'])
    seckey = os.path.expanduser(args['--sk'])
    if not args['-f']: # Don't force
        for k in (pubkey, seckey):
            if os.path.isfile(k):
                yn = input(f'{k} already exists. Do you want to overwrite it? (y/n) ')
                if yn != 'y':
                    print('Ok. Fair enough. Exiting.')
                    #sys.exit(0)
                    return
                
    do_crypt = not args['--nocrypt']
    cb = partial(getpass, prompt=f'Passphrase for {args["--sk"]}: ') if do_crypt else None
    comment = args['-C'].encode() if args['-C'] else None
    generate(seckey, pubkey, callback=cb, comment=comment)

def main(argv=sys.argv[1:]):
    try:
        run(argv)
    except KeyboardInterrupt:
        pass
    # except Exception as e:
    #     _, _, exc_tb = sys.exc_info()
    #     traceback.print_tb(exc_tb, file=sys.stderr)
    #     sys.exit(1)

if __name__ == '__main__':
    assert sys.version_info >= (3, 6), "This tool requires python version 3.6 or higher"
    main()
