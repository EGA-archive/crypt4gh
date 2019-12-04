import logging
from base64 import b64decode
import io

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from nacl.exceptions import CryptoError
from nacl.bindings.crypto_sign import crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519

from .kdf import derive_key
from ..exceptions import exit_on_invalid_passphrase

LOG = logging.getLogger(__name__)

# Internal cipher parameters
# ciphername => (block_size, key_size)
# Here, for those ciphers, IV size = block size
# Following this list: https://github.com/openssh/openssh-portable/blob/master/cipher.c#L86
_cipher_info = { 
    b"aes128-ctr"  : (16, 16),
    b"aes192-ctr"  : (16, 24),
    b"aes256-ctr"  : (16, 32),
    #b"blowfish-cbc": ( 8, 16),
    b"aes128-cbc"  : (16, 16),
    b"aes192-cbc"  : (16, 24),
    b"aes256-cbc"  : (16, 32),
    b"3des-cbc"    : ( 8, 24),
}

MAGIC_WORD = b'openssh-key-v1\x00'

def get_derived_key_length(ciphername):
    info = _cipher_info.get(ciphername)
    if info is None:
        raise ValueError(f'Unsupported cipher: {ciphername}')
    return sum(info)

def _block_size(ciphername):
    info = _cipher_info.get(ciphername)
    if info is None:
        raise ValueError(f'Unsupported cipher: {ciphername}')
    return info[0] # ivlen = block_size

def get_cipher(ciphername, derived_key):
    
    info = _cipher_info.get(ciphername)
    if info is None:
        raise ValueError(f'Unsupported cipher: {ciphername}')

    ivlen, keylen = info
    assert( len(derived_key) == sum(info) )
    key = derived_key[:keylen]
    iv = derived_key[keylen:]

    LOG.debug('Decryptiong Key (%d): %s', len(key), key.hex().upper())
    LOG.debug('IV (%d): %s', len(iv), iv.hex().upper())

    backend = default_backend()

    if ciphername in (b"aes128-ctr", b"aes192-ctr", b"aes256-ctr"):
        return Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)

    # if ciphername == b"blowfish-cbc":
    #     return Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=backend)

    if ciphername in (b"aes128-cbc", b"aes192-cbc", b"aes256-cbc"):
        return Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    if ciphername == b"3des-cbc":
        return Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
    
    # Should not come here
    raise ValueError(f'Unsupported cipher: {ciphername}')



def decode_string(stream):
    slen = int.from_bytes(stream.read(4), byteorder='big')
    data = stream.read(slen)
    # LOG.debug('Decoding string (len: %d): %s', slen, data)
    if len(data) != slen:
        raise ValueError("Invalid format: No enough data")
    return data


def _get_skpk_from_private_blob(blob):
    # We should parse n keys, but n is 1
    decode_string(blob) # ignore key name
    decode_string(blob) # ignore pubkey
    skpk = decode_string(blob)
    LOG.debug('Private Key blob: %s', skpk.hex().upper())
    assert len(skpk) == 64

    sk = skpk[:32] # first half = priv key
    LOG.debug('ed25519 sk: %s', sk.hex().upper())

    pk = skpk[32:] # second half = pub key
    LOG.debug('ed25519 pk: %s', pk.hex().upper())

    seckey = crypto_sign_ed25519_sk_to_curve25519(skpk)
    LOG.debug('x25519 sk: %s', seckey.hex().upper())

    pubkey = crypto_sign_ed25519_pk_to_curve25519(pk)
    LOG.debug('x25519 pk: %s', pubkey.hex().upper())

    return (seckey, pubkey)


@exit_on_invalid_passphrase
def parse_private_key(stream, callback):

    ciphername = decode_string(stream)
    kdfname = decode_string(stream)
    kdfoptions = decode_string(stream)

    LOG.info("Ciphername: %s", ciphername)
    LOG.info("KDF: %s", kdfname)
    # LOG.debug("KDF options %s", kdfoptions)

    if kdfname not in (b"none", b"bcrypt"):
        raise ValueError("Invalid SSH Key format")

    if kdfname != b"none" and ciphername == b"none":
        raise ValueError("Invalid SSH Key format")

    if kdfname != b'none':
        # assert (kdfname == b"bcrypt")
        assert kdfoptions
        kdfoptions = io.BytesIO(kdfoptions)
        salt = decode_string(kdfoptions)
        rounds = int.from_bytes(kdfoptions.read(4), byteorder='big')
        LOG.info("Salt: %s", salt.hex())
        LOG.info("Rounds: %d", rounds)
        assert not kdfoptions.read(), "There should be no trailing data in the kdfoptions buffer"
    else:
        LOG.debug("Not Encrypted")
        assert( not kdfoptions )


    n = int.from_bytes(stream.read(4), byteorder='big') # u32
    LOG.debug("Number of keys: %d", n)
    assert( n == 1 ) # Apparently always 1: https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L3857

    decode_string(stream) # ignore the public keys
    private_ciphertext = decode_string(stream) # padded list of private keys
    assert not stream.read(), "There should be no trailing data"

    if ciphername == b'none':
        # LOG.debug('Non-Encrypted private data: %s', private_data)
        private_data = io.BytesIO(private_ciphertext) # no need to unpad
        return _get_skpk_from_private_blob(private_data) # ignore the comment

    # Encrypted content
    # LOG.debug('------ Encrypted private data (%d): %s', len(private_ciphertext), private_ciphertext)
    assert( callback and callable(callback) )
    passphrase = callback().encode()
    # LOG.debug('Passphrase: %s', passphrase)

    if not passphrase and ciphername != b"none":
        raise ValueError("Passphrase required")

    dklen = get_derived_key_length(ciphername) # key length + IV length
    LOG.debug('Derived Key len: %d', dklen)
    derived_key = derive_key(kdfname, passphrase, salt, rounds, dklen=dklen) 
    LOG.debug('Derived Key: %s', derived_key)
    decryptor = get_cipher(ciphername, derived_key).decryptor()
    assert( len(private_ciphertext) % _block_size(ciphername) == 0 ), "Invalid cipher block length"
    private_data = decryptor.update(private_ciphertext) + decryptor.finalize()
    # LOG.debug('------- Private data (%d): %s', len(private_data), private_data)

    if private_data[:4] != private_data[4:8]: # check don't pass
        LOG.debug('Check: %s != %s', private_data[:4], private_data[4:8])
        raise CryptoError()
    private_data = io.BytesIO(private_data[8:])
    # Note: we ignore the comment and padding after the priv blob
    return _get_skpk_from_private_blob(private_data) # no need to unpad



# am I doing a lot of copying, while slicing ? Is Python smart enough?
def get_public_key(line):
    if line[4:12] != b'ed25519 ':
        raise NotImplementedError(f'Unsupported SSH key format: {line[0:11]}')
    pkey = b64decode(line[12:].split(b' ',1)[0]) # ignore the comment
    stream = io.BytesIO(pkey)

    key_type = decode_string(stream)
    assert( key_type == b'ssh-ed25519' )
    pubkey_bytes = decode_string(stream) # the rest is the ED25519 public key: it should be 32 bytes
    # Converting
    return crypto_sign_ed25519_pk_to_curve25519(pubkey_bytes)
    

