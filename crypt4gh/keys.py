# -*- coding: utf-8 -*-

import os
from base64 import b64decode, b64encode
import hashlib

import ed25519
from nacl.public import PrivateKey
from nacl.encoding import HexEncoder as KeyFormatter

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
    with open(verifying_key, 'wt') as pubfile, open(signing_key, 'wt') as privfile:
        pubfile.write(vk.to_bytes().hex())
        privfile.write(sk.to_bytes().hex())


if __name__ == '__main__':
    import sys
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    # import bcrypt
    # with open(sys.argv[1], 'rb') as f:
    #     lines = [line.strip() for line in f.readlines()]
    #     if (b'-----BEGIN OPENSSH PRIVATE KEY-----' != lines[0] or
    #         b'-----END OPENSSH PRIVATE KEY-----' != lines[-1]):
    #         print('Not an OpenSSH or SSH2 key')

    #     print('OPENSSH key format')
    #     b = b''.join([r for r in lines[1:-1] if not r.lower().startswith(b'comment: ') ])
    #     a = b64decode(b)
    #     print(a)
    #     print('='*30)
    #     ptr = 15
    #     print(a[:ptr])

    #     alg_len = int.from_bytes(a[ptr:ptr+4], 'big')
    #     print('alg len:', alg_len)
    #     ptr+=4
    #     alg = a[ptr:ptr+alg_len]
    #     print('alg:', alg)
    #     ptr+= alg_len

    #     kdf_len = int.from_bytes(a[ptr:ptr+4], 'big')
    #     print('kdf len:', kdf_len)
    #     ptr+= 4
    #     kdf = a[ptr:ptr+kdf_len]
    #     print('kdf:', kdf)
    #     ptr+= kdf_len

    #     kdf_buf_len = int.from_bytes(a[ptr:ptr+4], 'big')
    #     print('kdf buf len:', kdf_buf_len)
    #     ptr+= 4
    #     kdf_buf = a[ptr:ptr+kdf_buf_len]
    #     ptr+= kdf_buf_len

    #     salt_len = int.from_bytes(kdf_buf[:4], 'big')
    #     print('salt len:', salt_len)
    #     salt = kdf_buf[4:4+salt_len]
    #     print('salt:', salt)

    #     rounds = int.from_bytes(kdf_buf[4+salt_len:4+salt_len+4], 'big') # rounds is 4 bytes
    #     print('rounds:', rounds)


    #     nkeys = int.from_bytes(a[ptr:ptr+4], 'big')
    #     print('nkeys:', nkeys)
    #     ptr+= 4

    #     pubkey_len = int.from_bytes(a[ptr:ptr+4], 'big')
    #     print('pubkey len:', pubkey_len)
    #     ptr+=4
    #     pubkey = a[ptr:ptr+pubkey_len]
    #     print('pubkey:', pubkey)
    #     ptr+= pubkey_len

    #     # Parse Pubkey
    #     pubkey_type_len = int.from_bytes(pubkey[:4], 'big')
    #     pubkey_type = pubkey[4:4+pubkey_type_len]
    #     print('public key type:', pubkey_type)
    #     pubkey_content_len = int.from_bytes(pubkey[4+pubkey_type_len:pubkey_type_len+8], 'big')
    #     pubkey_content = pubkey[pubkey_type_len+8:pubkey_type_len+8+pubkey_content_len]
    #     print('public key:', pubkey_content.hex()) # 32 bytes

    #     # Parse Privkey
    #     encrypted_privkey_len = int.from_bytes(a[ptr:ptr+4], 'big')
    #     print('encrypted privkey len:', encrypted_privkey_len)
    #     ptr+=4
    #     encrypted_privkey = a[ptr:ptr+encrypted_privkey_len]
    #     print('encrypted privkey:', encrypted_privkey)
    #     ptr+= encrypted_privkey_len
    #     assert( encrypted_privkey_len == len(encrypted_privkey) )
    #     assert( a[ptr:] == b'' )


    #     h = bcrypt.kdf(password=sys.argv[2].encode(),
    #                      salt=salt,
    #                      desired_key_bytes=32+16,
    #                      rounds=rounds)
    #     key = h[:32]
    #     print('key:', key)
    #     iv = h[32:] # block size of aes256-cbc
    #     print('iv:', iv)
    #     backend = default_backend()
    #     cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    #     decryptor = cipher.decryptor()
    #     privkey = decryptor.update(encrypted_privkey) + decryptor.finalize()

    #     random_check = int.from_bytes(privkey[:4], 'big')
    #     random_check2 = int.from_bytes(privkey[4:8], 'big')
    #     if (random_check2 != random_check):
    #         print('Random check  :', random_check)
    #         print('Random check 2:', random_check2)
    #         print('Wrong passphrase')
    #         sys.exit(1)

    #     privkey = privkey[8:]
    #     print('privkey:', privkey)

    #     # key name
    #     name_len = int.from_bytes(privkey[:4], 'big')
    #     name = privkey[4:4+name_len]
    #     print('key name:', name)
    #     privkey = privkey[4+name_len:]

    #     # pub part again
    #     pkey_len = int.from_bytes(privkey[:4], 'big')
    #     pkey = privkey[4:4+pkey_len]
    #     print('public key:', pkey.hex())
    #     privkey = privkey[4+pkey_len:]

    #     # Private key
    #     seckey_len = int.from_bytes(privkey[:4], 'big')
    #     seckey = privkey[4:4+seckey_len]
    #     print('private key:', seckey.hex())
    #     privkey = privkey[4+seckey_len:]

    #     # Comment
    #     comment_len = int.from_bytes(privkey[:4], 'big')
    #     comment = privkey[4:4+comment_len]
    #     print('Comment:', comment)
        

        # # Test
        # sk = PrivateKey.generate()
        # pk = sk.public_key
        # print('gen pubkey:', pk.encode(KeyFormatter))
        # print('gen seckey:', sk.encode(KeyFormatter))

    from asn1crypto import pem
    from asn1crypto.core import ObjectIdentifier
    from asn1crypto.keys import EncryptedPrivateKeyInfo, PrivateKeyInfo, OctetString
    with open(sys.argv[3], 'rb') as f:
        der_bytes = f.read()
    if pem.detect(der_bytes):
        _, _, der_bytes = pem.unarmor(der_bytes)
    key = EncryptedPrivateKeyInfo.load(der_bytes)
    #print(key)
    enc = key['encryption_algorithm']
    #print(help(encryption_algorithm))
    #print(encryption_algorithm.map(encryption_algorithm['algorithm']))
    #assert encryption_algorithm['algorithm'] == 'pbes2', "Unsupported encryption algorithm"
    salt = enc.kdf_salt
    rounds = enc.kdf_iterations
    hash_alg = enc.kdf_hmac
    print('hash:',hash_alg)
    print('salt:',salt)
    print('rounds:',rounds)
    #key_length = encryption_algorithm.key_length if encryption_algorithm.key_length else 32
    #print('key_length:',key_length)
    #encryption_scheme = encryption_algorithm['encryption_scheme']
    passphrase = sys.argv[4].encode()
    print('passphrase:', passphrase)

    from pprint import pprint
    pprint(key.native)

    dk = hashlib.pbkdf2_hmac(hash_alg, passphrase, salt, int(rounds))
    print('key:', dk.hex(), len(dk))

    encrypted_data = key['encrypted_data']
    print('data:',encrypted_data)
    
    alg = enc.encryption_cipher
    print('alg:',alg)
    iv = enc.encryption_iv
    print('iv:',iv)
    mode = enc.encryption_mode
    print('mode:',mode)
    # alg = encryption_scheme['algorithm']
    # print('alg:',alg)
    # iv = encryption_scheme['parameters']
    # print('iv:',iv)

    cipher_alg = getattr(algorithms, alg.upper(), None)
    cipher_mode = getattr(modes, mode.upper(), None)
    if not cipher_alg or not cipher_mode:
        raise NotImplementedError('Unsupported algorithm')
    
    backend = default_backend()
    cipher = Cipher(cipher_alg(dk), cipher_mode(iv), backend=backend)
    decryptor = cipher.decryptor()
    privkey = decryptor.update(encrypted_data.native) + decryptor.finalize()

    print('decrypted data:', privkey.hex())

    from pyasn1.codec.der.decoder import decode

    thekey = decode(der_bytes)
    print(thekey)

    pkey = decode(privkey)
    print(pkey)
    data = pkey[0][2]

    print(data.asOctets().hex())
    # print('pubkey:', privkey[:32].hex())
    # print('privkey:', privkey[32:].hex())
    

#     data = bytes.fromhex('51F807195C69CE0B281B60417787DF5C107AAB8A0B951FC2F154ACDE6BB4FCAE526E200048DD75164169600B92CCD3AD7263C18F16FB3A
# 5F17F3B55D025646A8')
#     salt = bytes.fromhex('76F329189EA09BB1')
#     rounds = 2048
#     iv = bytes.fromhex('63B16CFC5F304FB011CB4EC96DB1D400')
    
#     key = 
#     cipher = Cipher(algorithms.ARS(dk), cipher_mode(iv), backend=backend)
#     decryptor = cipher.decryptor()
#     privkey = decryptor.update(encrypted_data.native) + decryptor.finalize()
