# -*- coding: utf-8 -*-

import os
import sys
import io
import logging
import hashlib
from hmac import compare_digest

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import ed25519
from nacl.public import SealedBox
from nacl.encoding import HexEncoder as KeyFormatter
from nacl.exceptions import InvalidkeyError, BadSignatureError, CryptoError

from . import __version__

LOG = logging.getLogger(__name__)

###########################################################
##
##         Crypt4GH header
##
###########################################################

MAGIC_NUMBER = b'crypt4gh'
BLOCK_SIZE = 65536 # 64kB

class Header():
    def __init__(self, version=__version__, encrypted_part=b'', mac=b'', verifying_key=None):
        self.version = version or __version__
        # Unencrypted part
        self._head = MAGIC_NUMBER + (version or __version__).to_bytes(4,'little')
        # Verifying key
        self.verifying_key = verifying_key or b''
        # Encrypted part
        self.encrypted_part = encrypted_part or b''
        # MAC
        self.mac = mac or b''
        # Adjusting the length
        self.unencrypted_part = self._head + len(self.verifying_key).to_bytes(4,'little') + self.verifying_key
        self.header_len = len(self.unencrypted_part) + len(self.encrypted_part) + 4 + len(self.mac)

    def encrypt(self, checksum, session_key, nonce, pubkey, method=0):
        '''Computes the encrypted part'''
        #LOG.debug('Encrypting using %s', pubkey.encode(KeyFormatter))
        data = (checksum +                    # 32 bytes
                method.to_bytes(4,'little') + # 4 bytes
                session_key +                 # 32 bytes
                nonce)                        # 12 bytes
        #LOG.debug('Original data: %s', data.hex())
        self.encrypted_part = SealedBox(pubkey).encrypt(data)
        #LOG.debug('Encrypted data: %s', self.encrypted_part.hex())
        self.header_len = len(self.unencrypted_part) + 4 + len(self.encrypted_part)

    def sign(self, signing_key):
        '''Computes the mac part'''
        assert( isinstance(signing_key, ed25519.SigningKey) )
        self.verifying_key = signing_key.get_verifying_key().to_bytes()

        # the unencrypted part becomes larger
        self.unencrypted_part = self._head + len(self.verifying_key).to_bytes(4,'little') + self.verifying_key
        self.header_len = len(self.unencrypted_part) + len(self.encrypted_part) + 4 + 64 # counting the mac in the length
        header = self.unencrypted_part + self.header_len.to_bytes(4,'little') + self.encrypted_part
        self.mac = signing_key.sign(header) #, encoding="base64")
        assert( len(self.mac) == 64 )

    def __bytes__(self):
        '''Serializes a header to a byte stream'''
        LOG.debug('Serializing the header (length: %d)', self.header_len)
        return self.unencrypted_part + self.header_len.to_bytes(4,'little') + self.encrypted_part + self.mac

    @classmethod
    def from_stream(cls, stream):
        '''Parses a given stream, verifies it and creates a Header object'''

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

        # Verifying key, 4 bytes
        verifying_key_len = int.from_bytes(bytes(buf[12:16]), byteorder='little')
        LOG.debug('Verifying Key Length: %d', verifying_key_len)
        verifying_key = None
        if verifying_key_len > 0:
            verifying_key = stream.read(verifying_key_len)
            buf += verifying_key
            vkey = ed25519.VerifyingKey(verifying_key)

        # Header length
        header_len = stream.read(4) # 4 bytes
        buf += header_len
        header_len = int.from_bytes(header_len, byteorder='little')

        encrypted_len = header_len - 16 - verifying_key_len - 4
        if verifying_key:
            encrypted_len -= 64 # discounting the mac from the length

        if encrypted_len <= 0: # Should be at least 16 bytes long
            raise ValueError('Invalid Header Length')

        # Encrypted part
        encrypted_part = bytearray(encrypted_len)
        if stream.readinto(encrypted_part) != encrypted_len:
            raise ValueError('Header too small')
        buf += encrypted_part

        # If case it is Ed25519 signed
        mac = None
        if verifying_key:
            mac = bytearray(64)
            if stream.readinto(mac) != 64:
                raise ValueError('Invalid MAC length')
            try:
                vkey.verify(bytes(mac), bytes(buf)) # raw bytes
            except ed25519.BadSignatureError:
                raise ValueError('Invalid Ed25519 signature')

        # Make the object
        obj = cls(version=version, encrypted_part=bytes(encrypted_part), mac=mac, verifying_key=verifying_key)
        return obj

    def __repr__(self):
        #return f'Crypt4GH Header {id(self)} | {bytes(self).hex()}'
        vkey = self.verifying_key.hex() if self.verifying_key else None
        mac = self.mac.hex() if self.mac else None
        return f'''Crypt4GH Header [id: {id(self)} | version: {self.version}]
        Unencrypted part: {self.unencrypted_part.hex()}
                  Length: {self.header_len}
           Verifying key: {vkey}
          Encrypted part: {self.encrypted_part.hex()}
                     MAC: {mac}
        '''

    def decrypt(self, seckey):
        #LOG.debug('Decrypting using %s', seckey.encode(KeyFormatter))
        #LOG.debug('Encrypted data: %s', self.encrypted_part.hex())
        data = SealedBox(seckey).decrypt(self.encrypted_part)
        #LOG.debug('Original data: %s', data.hex())
        if len(data) != 80: # 32+4+32+12
            raise ValueError('Invalid encrypted header part length')
        checksum = data[0:32]                                    # 32 bytes
        method = int.from_bytes(data[32:36], byteorder='little') # 4 bytes
        if method != 0:
            raise ValueError('Unsupported encryption method')
        session_key = data[36:68]                                # 32 bytes
        nonce = data[68:80]                                      # 12 bytes
        return (checksum, session_key, nonce, method)

    def reencrypt(self, pubkey, privkey, signing_key=None):
        '''Re-encrypt the given header'''
        LOG.info(f'Reencrypt the header')
        checksum, session_key, nonce, method = self.decrypt(privkey)
        # New header
        header = Header()
        header.encrypt(checksum, session_key, nonce, pubkey, method=method)
        if signing_key:
            header.sign(signing_key)
        return header

##############################################################
##
##    Decorator for Error Handling
##
##############################################################

def convert_error(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (InvalidkeyError, BadSignatureError, CryptoError) as e:
            LOG.error('Converting Crypto errors')
            raise ValueError('Crypt4GH Crypto Error') from e
    return wrapper

##############################################################
##
##    Symmetric encryption: Chacha20 (+ Poly1305)
##
##############################################################

def nonce_generator(nonce,counter=1):
    '''Increment a nonce value and a counter by 1 on each step'''
    b = bytearray(16)
    b[:12] = nonce
    b[12:16] = counter.to_bytes(4,'big')
    while True:
        yield bytes(b[:12])
        # Increment the counter
        pos = 15
        while True:
            if b[pos] == 255:
                b[pos] = 0
                pos -= 1 # next position
                if pos < 12:
                    return # Can't continue
            else:
                b[pos] += 1
                break
        # Increment the nonce
        pos = 11
        while True:
            if b[pos] == 255:
                b[pos] = 0
                pos -= 1 # next position
                if pos < 0:
                    break # wrap around
            else:
                b[pos] += 1
                break


def encrypt(infile, outfile, pubkey, signing_key=None):

    LOG.info('Encrypting the file')
    checksum = b'\x00' * 32 # False checksum, so far
    session_key = os.urandom(32)
    nonce = os.urandom(12)
    nonce_gen = nonce_generator(nonce, counter=1)

    LOG.debug('Creating Crypt4GH header')
    header = Header()
    header.encrypt(checksum, session_key, nonce, pubkey)
    if signing_key:
        header.sign(signing_key)
    header_bytes = bytes(header)
    outfile.write(header_bytes)

    LOG.debug("Streaming content")
    md = hashlib.sha256()
    cipher = ChaCha20Poly1305(session_key)

    chunk = infile.read(BLOCK_SIZE)
    while chunk:
        md.update(chunk)
        encrypted_data = cipher.encrypt(next(nonce_gen), chunk, None) # No aad
        outfile.write(encrypted_data)
        chunk = infile.read(BLOCK_SIZE)

    # Rewind to add the checksum
    LOG.debug("Rewinding to adjust the header")
    header = Header()
    header.encrypt(md.digest(), session_key, nonce, pubkey)
    if signing_key:
        header.sign(signing_key)
    real_header_bytes = bytes(header)
    assert( len(real_header_bytes) == len(header_bytes) )
    pos = outfile.tell() # record position
    outfile.seek(0, io.SEEK_SET) # from start
    outfile.write(real_header_bytes)
    LOG.debug("Replacing the file position")
    outfile.seek(pos, io.SEEK_SET) # go back to pos

    LOG.info('Encryption Successful')

# The optional process_output allows us to decrypt and:
# - dump the output to a file
# - not process the output (only checksum it internally)
# - send it (in mem) to another quality control pass

@convert_error
def body_decrypt(checksum, session_key, nonce, infile,
                 process_output=None,
                 nonce_count=1):
    '''Decrypting the data section and verifying its sha256 checksum'''
    LOG.info("Decrypting content")
    md = hashlib.sha256()
    cipher = ChaCha20Poly1305(session_key)
    nonce_gen = nonce_generator(nonce, counter=nonce_count)
    chunk_size = BLOCK_SIZE + 16

    do_process = callable(process_output)
    chunk = infile.read(chunk_size)
    while chunk:
        decrypted_data = cipher.decrypt(next(nonce_gen), chunk, None) # No aad
        md.update(decrypted_data)
        if do_process:
            process_output(decrypted_data)
        chunk = infile.read(chunk_size)

    # Rewind to add the checksum
    if not compare_digest(checksum, md.digest()):
        LOG.debug(f'Computed MDC: {md.hexdigest().upper()}')
        LOG.debug(f'Original MDC: {checksum.hex().upper()}')
        raise ValueError('Invalid checksum')

    LOG.info('Decryption Successful')

    
def decrypt(seckey, infile, process_output=None):
    LOG.info('Decrypting file')
    header = Header.from_stream(infile)
    #LOG.debug('Header is the header\n %s', header)
    checksum, session_key, nonce, method = header.decrypt(seckey)
    # Decrypt the rest
    return body_decrypt(checksum, session_key, nonce, infile, process_output=process_output)


def reencrypt(pubkey, privkey, infile, signing_key=None, process_output=lambda _:None, chunk_size=4096):
    '''Extract header and update with another one.
    The data section is only copied'''

    assert( callable(process_output) )

    encrypted_header = Header.from_stream(infile)
    header = encrypted_header.reencrypt(pubkey, privkey, signing_key=signing_key)
    process_output(bytes(header))

    LOG.info(f'Streaming the remainer of the file')
    while True:
        data = infile.read(chunk_size)
        if not data:
            break
        process_output(data)

    LOG.info('Reencryption Successful')
