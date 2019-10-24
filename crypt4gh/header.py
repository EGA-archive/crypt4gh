# -*- coding: utf-8 -*-
"""Generate and parse a Crypt4GH header."""

import os
import logging
from itertools import chain
from types import GeneratorType

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from nacl.bindings import crypto_kx_client_session_keys, crypto_kx_server_session_keys
from nacl.public import PrivateKey
from cryptography.exceptions import InvalidTag

from . import __version__

LOG = logging.getLogger(__name__)

PACKET_TYPE_DATA_ENC = 0
PACKET_TYPE_EDIT_LIST = 1

# Packet Types Conventions
# ------------------------
#
# 0: Data encryption parameters
# 1: Data Edit list
# else: NotSupported

PACKET_TYPE_DATA_ENC = 0
PACKET_TYPE_EDIT_LIST = 1

# -------------------------------------
# Header Envelope
# -------------------------------------

MAGIC_NUMBER = b'crypt4gh'

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

    # Packets count
    packets_count = int.from_bytes(bytes(buf[12:16]), byteorder='little')
    LOG.debug('This header contains %d packets', packets_count)

    # Spit out one packet at a time
    for i in range(packets_count):
        LOG.debug('========== Packet %d', i)
        encrypted_packet_len = int.from_bytes(stream.read(4), byteorder='little')
        LOG.debug('packet length: %d', encrypted_packet_len)
        if encrypted_packet_len < 0:
            raise ValueError(f'Invalid packet length {encrypted_packet_len}')
        encrypted_packet_data = stream.read(encrypted_packet_len)
        #LOG.debug('packet data: %s', encrypted_packet_data.hex())
        if len(encrypted_packet_data) < encrypted_packet_len:
            raise ValueError('Packet {} too small'.format(i))
        yield encrypted_packet_data


def serialize(packets):
    '''Serializes header packets to a byte stream'''
    if isinstance(packets, GeneratorType):
        packets = list(packets)
    if not packets:
        raise ValueError('No packets to serialize')
    packets_count = len(packets)
    LOG.debug('Serializing the header (%d packets)', packets_count)
    return (MAGIC_NUMBER +
            __version__.to_bytes(4,'little') +
            packets_count.to_bytes(4,'little') +
            b''.join( len(packet).to_bytes(4,'little') +
                      packet
                      for packet in packets ))

def make_packet_data_enc(encryption_method, session_key):
    return PACKET_TYPE_DATA_ENC.to_bytes(4,'little') + encryption_method.to_bytes(4,'little') + session_key

def make_packet_data_edit_list(edit_list):
    if isinstance(edit_list, GeneratorType):
        edit_list = list(edit_list)
    return (PACKET_TYPE_EDIT_LIST.to_bytes(4,'little') + 
            len(edit_list).to_bytes(4,'little') +
            b''.join( n1.to_bytes(4,'little') + n2.to_bytes(4,'little')
                      for (n1,n2) in edit_list ))


def partition_packets(packets):

    enc_packets = []
    edits = None

    for packet in packets:

        packet_type = packet[:4]

        if packet_type == b'\x00\x00\x00\x00': # 0 little endian
            enc_packets.append(packet[4:])

        elif packet_type == b'\x01\x00\x00\x00': # 1 little endian
            if edits is not None: # reject files if many edit list packets
                raise ValueError('Invalid file: Too many edit list packets')
            edits = packet[4:]

        else: # Bark if unsupported packet. Don't just ignore it
            packet_type = int.from_bytes(packet_type, byteorder='little')
            raise ValueError(f'Invalid packet type {packet_type}')

    return (enc_packets, edits)

def parse_enc_packet(packet):
    # if encryption_method != 0:
    encryption_method = packet[0:4]
    if encryption_method != b'\x00\x00\x00\x00': # 0 little endian
        LOG.warning('Unsupported bulk encryption method: %d', encryption_method)
        encryption_method = int.from_bytes(encryption_method, byteorder='little')
        raise ValueError(f'Unsupported bulk encryption method: {encryption_method}')
    session_key = packet[4:]
    return session_key

def parse_edit_list_packet(packet):
    nb_lengths = int.from_bytes(packet[:4], byteorder='little')
    LOG.debug('Edit list length: %d', nb_lengths)
    if nb_lengths < 0 or len(packet) - 4 < 8 * nb_lengths: # don't bark if longer
        raise ValueError('Invalid edit list')
    return [int.from_bytes(packet[i:i+8], byteorder='little') for i in range(4, (nb_lengths+1) * 8, 8)]

# -------------------------------------
# Header Encryption Methods Conventions
# -------------------------------------
#
# 0: chacha20_ietf_poly1305
# 1: AES-256-GCM ?
# else: NotImplemented / NotSupported

def encrypt_X25519_Chacha20_Poly1305(data, seckey, recipient_pubkey):
    '''Computes the encrypted part'''

    pubkey = bytes(PrivateKey(seckey).public_key)

    #LOG.debug('Original data: %s', data.hex())
    LOG.debug("         Packet data: %s", data.hex())
    LOG.debug('       my public key: %s', pubkey.hex())
    LOG.debug('       my secret key: %s', seckey.hex())
    LOG.debug('recipient public key: %s', recipient_pubkey.hex())

    # X25519 shared key
    _, shared_key = crypto_kx_server_session_keys(pubkey, seckey, recipient_pubkey)
    LOG.debug('shared key: %s', shared_key.hex())

    # Chacha20_Poly1305
    engine = ChaCha20Poly1305(shared_key)
    nonce = os.urandom(12)
    return (pubkey +
            nonce +
            engine.encrypt(nonce, data, None))  # No add

def decrypt_X25519_Chacha20_Poly1305(encrypted_part, privkey, sender_pubkey=None):
    #LOG.debug('-----------  Encrypted data: %s', encrypted_part.hex())
    LOG.debug('    my secret key: %s', privkey.hex())
    LOG.debug('Sender public key: %s', sender_pubkey.hex() if sender_pubkey else None)

    peer_pubkey = encrypted_part[:32]
    if sender_pubkey and sender_pubkey != peer_pubkey:
        raise ValueError("Invalid Peer's Public Key")

    nonce = encrypted_part[32:44]
    packet_data = encrypted_part[44:]

    LOG.debug('   peer pubkey: %s', peer_pubkey.hex())
    LOG.debug('         nonce: %s', nonce.hex())
    LOG.debug('encrypted data: %s', packet_data.hex())

    # X25519 shared key
    pubkey = bytes(PrivateKey(privkey).public_key)  # slightly inefficient, but working
    shared_key, _ = crypto_kx_client_session_keys(pubkey, privkey, peer_pubkey)
    LOG.debug('shared key: %s', shared_key.hex())

    # Chacha20_Poly1305
    engine = ChaCha20Poly1305(shared_key)
    return engine.decrypt(nonce, packet_data, None)  # No add


def decrypt_packet(packet, keys):
    '''Decrypt the packet, scanning all the `keys`

    `keys` is iterated and each item must be of the form (method, ...).
    
    Returns None if no key worked.
    '''
    packet_encryption_method = int.from_bytes(packet[:4], byteorder='little')
    LOG.debug('Header Packet Encryption Method: %d', packet_encryption_method)
    
    for method, *key in keys:
        
        if packet_encryption_method != method:
            continue # not a corresponding key anyway

        if packet_encryption_method == 0: # We try a chacha20 key
            try:
                privkey, sender_pubkey = key # must fit
                return decrypt_X25519_Chacha20_Poly1305(packet[4:], privkey, sender_pubkey=sender_pubkey)
            except InvalidTag as tag:
                LOG.error('Packet Decryption failed: %s', tag)
            except Exception as e: # Any other error, like (IndexError, TypeError, ValueError)
                LOG.error('Not a X25519 key: ignoring | %s', e)
                # try the next one

        elif packet_encryption_method == 1:
            LOG.warning('AES-256-GCM support is not implemented')

        else:
            LOG.error('Unsupported Header Encryption Method: %s', packet_encryption_method)

    return None # They all failed

# -------------------------------------
# Header Encryption Methods wrappers
# -------------------------------------
#
# Generators that try all the keys and yield header packets

def encrypt(packet, keys):
    '''Computes the encrypted part, using all `keys`

    `keys` is iterated and each item must be of the form (method, ...).

    We only support method=0.
    
    Returns None if no key worked.
    '''
    ''''''

    for method, *key in keys:

        if method != 0:
            LOG.warning('Unsupported key type (%d), skipping', method)
            continue

        try:
            seckey, recipient_pubkey = key
        except Exception as e:
            LOG.error('Not a X25519 key: ignoring | %s', e)
            continue

        # Otherwise, we encrypt with chacha20
        yield (method.to_bytes(4,'little') +
               encrypt_X25519_Chacha20_Poly1305(packet, seckey, recipient_pubkey))
        

def decrypt(encrypted_packets, keys):
    '''Partition the packets into those that we can be decrypt and the others.

    The output is 2 lists: one with decrypted packets and the other not understood encrypted packets'''

    decrypted_packets = []
    ignored_packets = []

    for packet in encrypted_packets:

        decrypted_packet = decrypt_packet(packet, keys)
        if decrypted_packet is None: # They all failed
            ignored_packets.append(packet)
        else:
            decrypted_packets.append(decrypted_packet)

    return (decrypted_packets, ignored_packets)


# -------------------------------------
# Header Re-Encryption
# -------------------------------------

def reencrypt(header_packets, keys, recipient_keys, trim=False):
    '''Re-encrypt the given header'''
    LOG.info(f'Reencrypting the header')

    decrypted_packets, ignored_packets = decrypt(header_packets, keys)

    packets = [encrypt(packet, recipient_keys) for packet in decrypted_packets]

    if not trim:
        packets.extend(ignored_packets)

    return packets


# -------------------------------------
# Header Re-Arrange
# -------------------------------------

def rearrange(header_packets, keys):
    '''Re-encrypt the given header'''
    LOG.info(f'Reencrypting the header')

    decrypted_packets, _ = decrypt(header_packets, keys) # ignore the other packets

    packets = [encrypt(packet, recipient_keys) for packet in decrypted_packets]

    return packets



