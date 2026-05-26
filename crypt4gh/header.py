# -*- coding: utf-8 -*-
"""Generate and parse a Crypt4GH header."""

import os
import logging
import time
from datetime import datetime
# from types import GeneratorType

from . import sodium, SEGMENT_SIZE, CIPHER_DIFF, SUPPORTED_VERSIONS

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
HEADER_ENCRYPTION_METHOD = b'\x00\x00\x00\x00' # 0 little endian, only supported method

def get_version(stream):
    '''Parses a given stream, verifies it and returns header's encrypted part'''

    buf = bytearray(12)
    if stream.readinto(buf) != 12:
        raise ValueError('Header too small')

    # Magic number, 8 bytes
    magic_number = bytes(buf[:8]) # 8 bytes
    if magic_number != MAGIC_NUMBER:
        LOG.error('Buf: %s', buf.hex())
        raise ValueError('Not a CRYPT4GH formatted file')

    # Version, 4 bytes
    version = int.from_bytes(bytes(buf[8:12]), byteorder='little')
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f'Unsupported CRYPT4GH version: {version}')

    return version

def parse(stream, version, sender_pubkey = None):

    # Sender pubkey if hoisted up in v2
    if version == 2:
        data = stream.read(36)
        if len(data) != 36:
            raise ValueError('Header v2 too small')
        header_encryption_method = int.from_bytes(data[:4], byteorder='little')
        LOG.debug('Header Packet Encryption Method: %d', header_encryption_method)
        peer_pubkey = data[4:]
        if sender_pubkey and sender_pubkey != peer_pubkey:
            raise ValueError("Invalid Peer's (signing) Public Key")

    # Packets count
    pcount = stream.read(4)
    if len(pcount) != 4:
        raise ValueError('Header v2 too small')
    packets_count = int.from_bytes(pcount, byteorder='little')
    LOG.debug('This header contains %d packets', packets_count)

    # Spit out one packet at a time
    for i in range(packets_count):
        LOG.debug('========== Packet %d', i)
        packet_len = int.from_bytes(stream.read(4), byteorder='little') - 4 # includes packet_len itself
        LOG.debug('packet length: %d', packet_len)
        if packet_len < 0:
            raise ValueError(f'Invalid packet length {packet_len}')
        packet_data = stream.read(packet_len)
        #LOG.debug('packet data: %s', packet_data.hex())
        if len(packet_data) < packet_len:
            raise ValueError('Packet {} too small'.format(i))

        if version == 2:
            yield (header_encryption_method, peer_pubkey, packet_data)

        else: # v1
            if len(packet_data) < 36:
                raise ValueError('Header packet v1 too small')

            header_encryption_method = int.from_bytes(packet_data[:4], byteorder='little')
            LOG.debug('Header Packet Encryption Method: %d', header_encryption_method)

            peer_pubkey = packet_data[4:36]
            if sender_pubkey and sender_pubkey != peer_pubkey:
                # raise ValueError("Invalid Peer's (signing) Public Key")
                LOG.error("Invalid Peer's (signing) Public Key")
                continue # skipping
 
            yield (header_encryption_method, peer_pubkey, packet_data[36:])


def serialize(version, writer_pubkey, packets):
    '''Serializes header packets to a byte stream'''

    assert version in SUPPORTED_VERSIONS, f'Unsupported version: {version}'
    assert writer_pubkey, "Missing writer's public key"
    assert packets, 'No packets to serialize'

    preamble = MAGIC_NUMBER + version.to_bytes(4,'little')

    if version == 2:
        preamble = preamble + HEADER_ENCRYPTION_METHOD + writer_pubkey

    # handle packets
    packets_count = len(packets)
    LOG.debug('Serializing the header (%d packets) | version: %s', packets_count, version)

    _packets = []
    for packet in packets:
        if version == 1:
            data = HEADER_ENCRYPTION_METHOD + writer_pubkey + packet
        if version == 2:
            data = packet
        _packets.append( (len(data) + 4).to_bytes(4,'little') + data )

    return (preamble
            + packets_count.to_bytes(4,'little')
            + b''.join(_packets))

# -------------------------------------
# Packet types
# -------------------------------------

PACKET_TYPE_DATA_ENC  = b'\x00\x00\x00\x00' # 0 little endian
PACKET_TYPE_EDIT_LIST = b'\x01\x00\x00\x00' # 1 little endian
PACKET_TYPE_TIMESTAMP = b'\x02\x00\x00\x00' # 2 little endian
PACKET_TYPE_LINK      = b'\x03\x00\x00\x00' # 3 little endian

# -------------------------------------
# Encrypted data packet
# ------------------------------------
def make_packet_data_enc(session_key, seqnum):

    if seqnum is None: # v1
        encryption_method = 0 # chacha20_poly1305, no AEAD
        return (PACKET_TYPE_DATA_ENC
                + encryption_method.to_bytes(4,'little') 
                + session_key)
    # else v2
    assert isinstance(seqnum, int)
    encryption_method = 1 # chacha20_poly1305, with AEAD
    return (PACKET_TYPE_DATA_ENC
            + encryption_method.to_bytes(4,'little') 
            + session_key
            + seqnum.to_bytes(8, 'little'))

def parse_packet_data_enc(packet):
    encryption_method = int.from_bytes(packet[0:4], byteorder='little')
    if encryption_method == 0:
        if len(packet) < 36:
            raise f"Data Encryption Packet too short (method: {encryption_method})"
        session_key = packet[4:]
        return (0, session_key, None)

    if encryption_method == 1:
        if len(packet) < 44:
            raise f"Data Encryption Packet too short (method: {encryption_method})"
        session_key = packet[4:36]
        seqnum = int.from_bytes(packet[36:44], byteorder='little', signed=False)
        return (1, session_key, seqnum)

    raise ValueError(f'Unsupported bulk encryption method: {encryption_method}')

# -------------------------------------
# Edit list packet
# -------------------------------------
def make_packet_edit_list(edit_list):
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

def parse_packet_edit_list(packet):
    '''Returns a generator to produce the `lengths` numbers from the `packet` bytes'''
    nb_lengths = int.from_bytes(packet[:4], byteorder='little')
    LOG.debug('Edit list length: %d', nb_lengths)
    LOG.debug('packet content length: %d', len(packet) - 4)
    if nb_lengths < 0 or len(packet) - 4 < 8 * nb_lengths: # don't bark if longer
        raise ValueError('Invalid edit list')
    return (int.from_bytes(packet[i:i+8], byteorder='little') for i in range(4, nb_lengths * 8, 8)) # generator


# -------------------------------------
# Timestamp packet
# -------------------------------------
def make_packet_timestamp(timestamp):
    return (PACKET_TYPE_TIMESTAMP
            + int(timestamp).to_bytes(8,'little')) # we drop the milliseconds

def parse_packet_timestamp(packet):
    if len(packet) != 8:
        raise ValueError('Invalid timestamp packet length')
    return int.from_bytes(packet, byteorder='little')

# -------------------------------------
# link packet
# -------------------------------------
def make_packet_link(link):
    return (PACKET_TYPE_LINK
            + link.encode())

def parse_packet_link(packet):
    return packet.decode()

# -------------------------------------
# Header Encryption Methods Conventions
# -------------------------------------
#
# 0: chacha20_ietf_poly1305
# 1: AES-256-GCM ?
# else: NotImplemented / NotSupported

def encrypt_X25519_Chacha20_Poly1305(data, seckey, pubkey, recipient_pubkey):

    # X25519 shared key
    shared_key = sodium.kx_server(pubkey, seckey, recipient_pubkey)

    # LOG.debug('    my secret key: %s', seckey.hex())
    # LOG.debug('    my public key: %s', pubkey.hex())
    # LOG.debug(' recipient pubkey: %s', recipient_pubkey.hex())
    # LOG.debug('       shared key: %s', shared_key.hex())

    encrypted_data = bytearray(len(data) + CIPHER_DIFF)
    # Chacha20_Poly1305 (including nonce), no AEAD
    clen = sodium.chacha20poly1305_encrypt(encrypted_data, data, shared_key, None)
    return encrypted_data[:clen]
    

def decrypt_X25519_Chacha20_Poly1305(packet, seckey, pubkey, peer_pubkey):

    # X25519 shared key
    shared_key = sodium.kx_client(pubkey, seckey, peer_pubkey)

    # LOG.debug('    my secret key: %s', seckey.hex())
    # LOG.debug('    my public key: %s', pubkey.hex())
    # LOG.debug('      peer pubkey: %s', peer_pubkey.hex())
    # LOG.debug('       shared key: %s', shared_key.hex())
    # LOG.debug('   encrypted data: [%d] %s', len(packet), packet.hex())

    decrypted_data = bytearray(len(packet)) # larger then needed
    plen = sodium.chacha20poly1305_decrypt(decrypted_data, packet, shared_key, None)
    return decrypted_data[:plen]


# -------------------------------------
# Header Encryption Methods wrappers
# -------------------------------------

def construct(version, seckey, recipient_keys,
              session_key, seqnum, edits, expiration, uri):
    assert ((version == 1 and seqnum is None)
            or
            (version == 2 and isinstance(seqnum, int))), "Invalid parameters"

    LOG.debug('Constructing Crypt4GH header (v%s) | SeqNum: %s', version, seqnum)
    packets = [make_packet_data_enc(session_key, seqnum)]
    if expiration is not None:
        packets.append( make_packet_timestamp(expiration) )
    if edits is not None:
        packets.append( make_packet_edit_list(edits) )
    if uri is not None:
        packets.append( make_packet_link(uri) )

    pubkey = sodium.derive_pk(seckey)
    encrypted_packets = []
    for packet in packets:
        for recipient_pubkey in recipient_keys:
            encrypted_packets.append( encrypt_X25519_Chacha20_Poly1305(packet, seckey, pubkey, recipient_pubkey) )

    return serialize(version, pubkey, encrypted_packets)

def check_integrity(packets):

    has_timestamp = False
    has_edit_list = False
    has_link = False

    for packet in packets:

        packet_type = packet[:4]

        if packet_type == PACKET_TYPE_DATA_ENC:
            pass

        elif packet_type == PACKET_TYPE_EDIT_LIST:
            if has_edit_list: # reject files if many edit list packets
                raise ValueError('Invalid file: Too many edit list packets')
            has_edit_list = True

        elif packet_type == PACKET_TYPE_TIMESTAMP:
            if has_timestamp: # reject files if many timestamp
                raise ValueError('Invalid file: Too many timestamp packets')
            has_timestamp = True
            expiration = parse_packet_timestamp(packet[4:])
            if time.time() > expiration: # now > expiration
                raise ValueError(f'Expired on {datetime.fromtimestamp(expiration)}')

        elif packet_type == PACKET_TYPE_LINK:
            if has_link: # reject files if many link packets
                raise ValueError('Invalid file: Too many link packets')
            has_link = True

        else: # Bark if unsupported packet. Don't just ignore it
            packet_type = int.from_bytes(packet_type, byteorder='little')
            raise ValueError(f'Invalid packet type {packet_type}')


def decrypt(encrypted_packets, seckey, pubkey):
    '''Partition the packets into those that we can be decrypt and the others.

    :returns: A list of decrypted packets and another list of undecryptable encrypted packets'''

    decrypted_packets = []
    ignored_packets = []

    for header_encryption_method, peer_pubkey, packet in encrypted_packets:

        if header_encryption_method != 0: # only supported method
            continue # not a corresponding key anyway

        try:
            decrypted_packet = decrypt_X25519_Chacha20_Poly1305(packet, seckey, pubkey, peer_pubkey)
            decrypted_packets.append(decrypted_packet)
        except Exception as e:
            LOG.error('X25519 Packet Decryption failed: %s', e)
            ignored_packets.append(packet)

    check_integrity(decrypted_packets)

    return (decrypted_packets, ignored_packets)


def deconstruct(infile, seckey, sender_pubkey=None):

    pubkey = sodium.derive_pk(seckey)

    version = get_version(infile)
    header_packets = parse(infile, version, sender_pubkey=sender_pubkey)
    decrypted_packets, _ = decrypt(header_packets, seckey, pubkey)  # don't bother with ignored packets

    if not decrypted_packets: # no packets were decrypted
        raise ValueError('No header packet could be decrypted')

    # Parse packets, we already checked the packets' list integrity
    data_encryptions = []
    edit_list = None
    timestamp = None
    link = None

    for packet in decrypted_packets:

        packet_type = packet[:4]

        if packet_type == PACKET_TYPE_DATA_ENC: 
            data_encryptions.append( parse_packet_data_enc(packet[4:]) )

        elif packet_type == PACKET_TYPE_EDIT_LIST:
            edit_list = parse_packet_edit_list(packet[4:])

        elif packet_type == PACKET_TYPE_TIMESTAMP:
            timestamp = parse_packet_timestamp(packet[4:])

        elif packet_type == PACKET_TYPE_LINK:
            link = parse_packet_link(packet[4:])

    return (version, data_encryptions, edit_list, timestamp, link)

# -------------------------------------
# Header Re-Encryption
# -------------------------------------

def reencrypt(infile, seckey, recipient_keys,
              sender_pubkey = None,
              uri = None,
              version = 1):

    LOG.info('Reencrypting the header')

    pubkey = sodium.derive_pk(seckey)

    org_version = get_version(infile)
    header_packets = parse(infile, org_version, sender_pubkey=sender_pubkey)
    decrypted_packets, _ = decrypt(header_packets, seckey, pubkey)  # don't bother with ignored packets

    if not decrypted_packets:
        raise ValueError('No header packet could be decrypted')

    if uri:
        LOG.info('Adding new URI packet: %s', uri)
        packets = [make_packet_link(uri)]
        # filter out the URI packet. We already check the packets' list integrity
        for packet in decrypted_packets:
            if packet[:4] == PACKET_TYPE_LINK:
                LOG.warning('Ignoring existing link: %s', parse_packet_link(packet[4:]))
                # don't append, filter it out
            else:
                packets.append(packet)

    else:
        packets = decrypted_packets

    # Re-encrypt
    encrypted_packets = []
    for packet in packets:
        for recipient_pubkey in recipient_keys:
            encrypted_packets.append( encrypt_X25519_Chacha20_Poly1305(packet, seckey, pubkey, recipient_pubkey) )

    return serialize(version, pubkey, encrypted_packets)
