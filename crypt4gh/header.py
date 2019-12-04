# -*- coding: utf-8 -*-
"""Generate and parse a Crypt4GH header."""

import os
import logging
from itertools import chain
# from types import GeneratorType

from nacl.bindings import (crypto_kx_client_session_keys,
                           crypto_kx_server_session_keys,
                           crypto_aead_chacha20poly1305_ietf_encrypt,
                           crypto_aead_chacha20poly1305_ietf_decrypt)
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey

from . import SEGMENT_SIZE, VERSION

LOG = logging.getLogger(__name__)

# Packet Types Conventions
# ------------------------
#
# 0: Data encryption parameters
# 1: Data Edit list
# else: NotSupported

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
    if version != VERSION: # only version 1, so far
        raise ValueError('Unsupported CRYPT4GH version')

    # Packets count
    packets_count = int.from_bytes(bytes(buf[12:16]), byteorder='little')
    LOG.debug('This header contains %d packets', packets_count)

    # Spit out one packet at a time
    for i in range(packets_count):
        LOG.debug('========== Packet %d', i)
        encrypted_packet_len = int.from_bytes(stream.read(4), byteorder='little') - 4 # include packet_len itself
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
    packets = list(packets)
    # if isinstance(packets, GeneratorType):
    #     packets = list(packets)
    if not packets:
        raise ValueError('No packets to serialize')
    packets_count = len(packets)
    LOG.debug('Serializing the header (%d packets)', packets_count)
    return (MAGIC_NUMBER +
            VERSION.to_bytes(4,'little') +
            packets_count.to_bytes(4,'little') +
            b''.join( (len(packet) + 4).to_bytes(4,'little') +
                      packet
                      for packet in packets ))

# -------------------------------------
# Encrypted data packet
# -------------------------------------

PACKET_TYPE_DATA_ENC = b'\x00\x00\x00\x00'  # 0 little endian
PACKET_TYPE_EDIT_LIST = b'\x01\x00\x00\x00' # 1 little endian

def partition_packets(packets):

    enc_packets = []
    edits = None

    for packet in packets:

        packet_type = packet[:4]

        if packet_type == PACKET_TYPE_DATA_ENC: 
            enc_packets.append(packet[4:])

        elif packet_type == PACKET_TYPE_EDIT_LIST:
            if edits is not None: # reject files if many edit list packets
                raise ValueError('Invalid file: Too many edit list packets')
            edits = packet[4:]

        else: # Bark if unsupported packet. Don't just ignore it
            packet_type = int.from_bytes(packet_type, byteorder='little')
            raise ValueError(f'Invalid packet type {packet_type}')

    return (enc_packets, edits)

# -------------------------------------
# Encrypted data packet
# -------------------------------------
def make_packet_data_enc(encryption_method, session_key):
    return (PACKET_TYPE_DATA_ENC
            + encryption_method.to_bytes(4,'little') 
            + session_key)

def parse_enc_packet(packet):
    # if encryption_method != 0:
    encryption_method = packet[0:4]
    if encryption_method != b'\x00\x00\x00\x00': # 0 little endian
        LOG.warning('Unsupported bulk encryption method: %s', encryption_method)
        encryption_method = int.from_bytes(encryption_method, byteorder='little')
        raise ValueError(f'Unsupported bulk encryption method: {encryption_method}')
    session_key = packet[4:]
    return session_key

# -------------------------------------
# Edit list packet
# -------------------------------------
def make_packet_data_edit_list(edit_list):
    edit_list = list(edit_list)
    # if isinstance(edit_list, GeneratorType):
    #     edit_list = list(edit_list)
    return (PACKET_TYPE_EDIT_LIST
            + len(edit_list).to_bytes(4,'little')
            + b''.join( n.to_bytes(8,'little') for n in edit_list ))

def validate_edit_list(edits):
    '''Some (obvious) validation'''
    if any(n < 0 for n in edits):
        raise ValueError('Invalid edit list: Cannot use negative numbers')
    if not all(skip < 2 * SEGMENT_SIZE - 1 for skip in edits[0::2]):
        raise ValueError('Invalid edit list: Data blocks will be ignored')
    if not all(skip > edits[2::2]): # all but first
        raise ValueError('Invalid edit list: Cannot skip 0 bytes in between reads')
    if not (edits[0] < SEGMENT_SIZE):
        raise ValueError('Invalid edit list: First data block is ignored')

def parse_edit_list_packet(packet):
    '''Returns a generator to produce the `lengths` numbers from the `packet` bytes'''
    nb_lengths = int.from_bytes(packet[:4], byteorder='little')
    LOG.debug('Edit list length: %d', nb_lengths)
    LOG.debug('packet content length: %d', len(packet) - 4)
    if nb_lengths < 0 or len(packet) - 4 < 8 * nb_lengths: # don't bark if longer
        raise ValueError('Invalid edit list')
    return (int.from_bytes(packet[i:i+8], byteorder='little') for i in range(4, nb_lengths * 8, 8)) # generator

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
    nonce = os.urandom(12)
    encrypted_data = crypto_aead_chacha20poly1305_ietf_encrypt(data, None, nonce, shared_key)  # no add
    return (pubkey + nonce + encrypted_data)

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
    return crypto_aead_chacha20poly1305_ietf_decrypt(packet_data, None, nonce, shared_key)  # no add


def decrypt_packet(packet, keys, sender_pubkey=None):
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
                privkey, _ = key # must fit
                return decrypt_X25519_Chacha20_Poly1305(packet[4:], privkey, sender_pubkey=sender_pubkey)
            except CryptoError as tag:
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
    
    :returns: None if no key worked, the decrypted packet otherwise
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
        

def decrypt(encrypted_packets, keys, sender_pubkey=None):
    '''Partition the packets into those that we can be decrypt and the others.

    :returns: A list of decrypted packets and another list of undecryptable encrypted packets'''

    decrypted_packets = []
    ignored_packets = []

    for packet in encrypted_packets:

        decrypted_packet = decrypt_packet(packet, keys, sender_pubkey=sender_pubkey)
        if decrypted_packet is None: # They all failed
            ignored_packets.append(packet)
        else:
            decrypted_packets.append(decrypted_packet)

    return (decrypted_packets, ignored_packets)


def deconstruct(infile, keys, sender_pubkey=None):
    """Retrieve the header from the `infile` stream, and decrypts it.

    Leaves the infile stream right after the header.

    :return: a pair with a list of session keys and a generator of lengths from an edit list (or None if there was no edit list).
    :rtype: (list of bytes, int generator or None)

    :raises: ValueError if the header could not be decrypted
    """
    header_packets = parse(infile)
    packets, _ = decrypt(header_packets, keys, sender_pubkey=sender_pubkey)  # don't bother with ignored packets

    if not packets: # no packets were decrypted
        raise ValueError('No supported encryption method')

    data_packets, edit_packet = partition_packets(packets)
    # Parse returns the session key (since it should be method 0) 
    session_keys = [parse_enc_packet(packet) for packet in data_packets]
    edit_list = parse_edit_list_packet(edit_packet) if edit_packet else None
    return session_keys, edit_list

# -------------------------------------
# Header Re-Encryption
# -------------------------------------

def reencrypt(header_packets, keys, recipient_keys, trim=False):
    '''Re-encrypt the given header.

    :returns: new list of packets'''
    LOG.info('Reencrypting the header')

    decrypted_packets, ignored_packets = decrypt(header_packets, keys)

    if not decrypted_packets:
        raise ValueError('No header packet could be decrypted')

    packets = [encrypted_packet for packet in decrypted_packets for encrypted_packet in encrypt(packet, recipient_keys)]

    if not trim:
        packets.extend(ignored_packets)

    return packets


# -------------------------------------
# Header Re-Arrange
# -------------------------------------

def rearrange(header_packets, keys, offset=0, span=None, sender_pubkey=None):
    '''Re-arrange the edit list in accordance to the [start;end] range.
    
    :returns: the data_packet as-is, a new edit list packet, along with an "oracle".
    
    The oracle tells if the "next" segment should be kept (starting by the first).
    '''

    LOG.info('Rearranging the header')

    LOG.debug("  Start Coordinate: %s", offset)
    LOG.debug("    End Coordinate: %s", offset + span if span else 'EOF')
    LOG.debug("      Segment size: %s", SEGMENT_SIZE)

    assert( isinstance(offset, int) and offset >= 0 and (span is None or (isinstance(span, int) and span > 0)) )

    if offset == 0 and span is None:
        raise ValueError('Nothing to be done')

    # Ok, we have a range as [start; end] or just [start; EOF]
    # Decrypt the packets, and get to the edit list
    # Undecryptable packets are tossed away

    decrypted_packets, _ = decrypt(header_packets, keys, sender_pubkey=sender_pubkey)

    if not decrypted_packets:
        raise ValueError('No header packet could be decrypted')

    data_packets, edit_packet = partition_packets(decrypted_packets)

    #
    # Note: We do not yet implement chunking a file that already contains an Edit List
    #
    if edit_packet is not None:
        raise NotImplementedError('Not implemented yet')

    LOG.info('No edit list present: making one')

    start_segment, start_offset = divmod(offset, SEGMENT_SIZE)
    end_segment, end_offset = divmod(offset+span, SEGMENT_SIZE) if span else (None,None)

    LOG.debug('Start segment: %d | Offset: %d', start_segment, start_offset)
    LOG.debug('  End segment: %s | Offset: %s', end_segment, end_offset)


    # This oracle tells you whether you should keep the current segment every time you ask
    def segment_oracle():
        count = 0
        while True:
            if count < start_segment:
                yield False
            else:
                if end_segment:
                    yield (count < end_segment or (count == end_segment and end_offset > 0))
                else:
                    yield True
            count += 1

    edit_list = [start_offset]
    if span:
        edit_list.append(span)

    LOG.debug('New edit list: %s', edit_list)
    edit_packet = make_packet_data_edit_list(edit_list)

    LOG.info('Reencrypting all packets')

    packets = [PACKET_TYPE_DATA_ENC + packet for packet in data_packets]
    packets.append(edit_packet) # adding the edit list at the end
    packets = [encrypted_packet for packet in packets for encrypted_packet in encrypt(packet, keys)]

    return packets, segment_oracle()


