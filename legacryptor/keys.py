# -*- coding: utf-8 -*-

import ed25519
from nacl.public import PrivateKey
from nacl.encoding import HexEncoder as KeyFormatter
#from nacl.encoding import URLSafeBase64Encoder as KeyFormatter


# def _generate_derived_key(password, salt=None, iterations=None):
#   """
#   Generate a derived key by feeding 'password' to the Password-Based Key
#   Derivation Function (PBKDF2).  pyca/cryptography's PBKDF2 implementation is
#   used in this module.  'salt' may be specified so that a previous derived key
#   may be regenerated, otherwise '_SALT_SIZE' is used by default.  'iterations'
#   is the number of SHA-256 iterations to perform, otherwise
#   '_PBKDF2_ITERATIONS' is used by default.
#   """

#   # Use pyca/cryptography's default backend (e.g., openSSL, CommonCrypto, etc.)
#   # The default backend is not fixed and can be changed by pyca/cryptography
#   # over time.
#   backend = default_backend()

#   # If 'salt' and 'iterations' are unspecified, a new derived key is generated.
#   # If specified, a deterministic key is derived according to the given
#   # 'salt' and 'iterrations' values.
#   if salt is None:
#     salt = os.urandom(_SALT_SIZE)

#   if iterations is None:
#     iterations = _PBKDF2_ITERATIONS

#   # Derive an AES key with PBKDF2.  The  'length' is the desired key length of
#   # the derived key.
#   pbkdf_object = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
#        iterations=iterations, backend=backend)

#   derived_key = pbkdf_object.derive(password.encode('utf-8'))

#   return salt, iterations, derived_key



def generate_ec(seckey, pubkey, passphrase=None):

    # Generate the keys
    sk = PrivateKey.generate()
    pk = sk.public_key

    # TODO: Encrypt the private key (like passphrase -> key, and AES)

    with open(pubkey, 'bw') as pubfile, open(seckey, 'bw') as privfile:
        pubfile.write(pk.encode(KeyFormatter))
        privfile.write(sk.encode(KeyFormatter))

def generate_signing(signing_key, verifying_key, passphrase=None):

    # Generate the keys
    sk, vk = ed25519.create_keypair()

    # TODO: Encrypt the private key (like passphrase -> key, and AES)

    # signing_key: private part, verifying_key: public part
    with open(verifying_key, 'bw') as pubfile, open(signing_key, 'bw') as privfile:
        pubfile.write(vk.to_bytes())
        privfile.write(sk.to_bytes())

