# -*- coding: utf-8 -*-
"""Handle the encryption of the application data."""

import os
import logging
import io
import collections

from nacl.bindings import (crypto_aead_chacha20poly1305_ietf_encrypt,
                           crypto_aead_chacha20poly1305_ietf_decrypt)
from nacl.exceptions import CryptoError


from . import SEGMENT_SIZE
from .exceptions import close_on_broken_pipe
from . import header

LOG = logging.getLogger(__name__)

CIPHER_DIFF = 28
CIPHER_SEGMENT_SIZE = SEGMENT_SIZE + CIPHER_DIFF

# Encryption Methods Conventions
# ------------------------------
#
# 0: chacha20_ietf_poly1305
# 1: AES-256-CTR => Not Implemented
# else: NotSupported


##############################################################
##
##    Symmetric encryption - Chacha20_Poly1305
##
##############################################################

def _encrypt_segment(data, process, key):
    '''Utility function to generate a nonce, encrypt data with Chacha20, and authenticate it with Poly1305.'''

    #LOG.debug("Segment [%d bytes]: %s..%s", len(data), data[:10], data[-10:])

    nonce = os.urandom(12)
    encrypted_data = crypto_aead_chacha20poly1305_ietf_encrypt(data, None, nonce, key)  # no add
    process(nonce) # after producing the segment, so we don't start outputing when an error occurs
    process(encrypted_data)


@close_on_broken_pipe
def encrypt(keys, infile, outfile, offset=0, span=None):
    '''Encrypt infile into outfile, using the list of keys.


    It fast-forwards to `offset` and encrypts until
    a total of `span` bytes is reached (or to EOF if `span` is None)

    This produces a Crypt4GH file without edit list.
    '''

    LOG.info('Encrypting the file')

    # Forward to start position
    LOG.debug("  Start Coordinate: %s", offset)
    try:
        offset = int(offset)
        if offset < 0:
            offset = 0
            LOG.error('Invalid start coordinate. Using 0 instead')
    except Exception as e:
        LOG.error("Conversion error: %s", e)
        offset = 0

    if offset: # not 0
        LOG.info("Forwarding to position: %s", offset)
        infile.seek(offset, io.SEEK_SET)

    # Where to stop
    if isinstance(span, int) and span <= 0:
        LOG.error("    Span: %s | Converting to None", span)
        span = None

    LOG.debug("    Span: %s", span)

    # Preparing the encryption engine
    encryption_method = 0 # only choice for this version
    session_key = os.urandom(32) # we use one session key for all blocks

    # Output the header
    LOG.debug('Creating Crypt4GH header')
    header_content = header.make_packet_data_enc(encryption_method, session_key)
    header_packets = header.encrypt(header_content, keys)
    header_bytes = header.serialize(header_packets)

    LOG.debug('header length: %d', len(header_bytes))
    outfile.write(header_bytes)

    # ...and cue music
    LOG.debug("Streaming content")
    # oh boy... I buffer a whole segment!
    # TODO: Use a smaller buffer (Requires code rewrite)
    segment = bytearray(SEGMENT_SIZE)

    if span is None:
        # The whole file
        while True:
            segment_len = infile.readinto(segment)

            if segment_len == 0: # finito
                break

            if segment_len < SEGMENT_SIZE: # not a full segment
                data = bytes(segment[:segment_len]) # to discard the bytes from the previous segments
                _encrypt_segment(data, outfile.write, session_key)
                break

            data = bytes(segment) # this is a full segment
            _encrypt_segment(data, outfile.write, session_key)

    else: # we have a max size
        assert( span )

        while span > 0:

            segment_len = infile.readinto(segment)

            data = bytes(segment) # this is a full segment

            if segment_len < SEGMENT_SIZE: # not a full segment
                data = data[:segment_len] # to discard the bytes from the previous segments

            if span < segment_len: # stop early
                data = data[:span]
                _encrypt_segment(data, outfile.write, session_key)
                break

            _encrypt_segment(data, outfile.write, session_key)

            span -= segment_len

            if segment_len < SEGMENT_SIZE: # not a full segment
                break

    LOG.info('Encryption Successful')


##############################################################
##
##    Symmetric decryption - Chacha20_Poly1305
##
##############################################################

def cipher_chunker(f, size):
    while True:
        ciphersegment = f.read(size)
        ciphersegment_len = len(ciphersegment)
        if ciphersegment_len == 0: 
            break # We were at the last segment. Exits the loop
        assert( ciphersegment_len > CIPHER_DIFF )
        yield ciphersegment

def decrypt_block(ciphersegment, session_keys):
    # Trying the different session keys (via the cipher objects)
    # Note: we could order them and if one fails, we move it at the end of the list
    # So... LRU solution. For now, try them as they come.
    nonce = ciphersegment[:12]
    data = ciphersegment[12:]

    for key in session_keys:
        try:
            return crypto_aead_chacha20poly1305_ietf_decrypt(data, None, nonce, key)  # no add, and break the loop
        except CryptoError as tag:
            LOG.error('Decryption failed: %s', tag)
    else: # no cipher worked: Bark!
        raise ValueError('Could not decrypt that block')

class ProcessingOver(Exception):
    pass

def limited_output(offset=0, limit=None, process=None):
    '''Generator that receives clear text and does not process more than limit bytes (if limit is not None).

    Raises ProcessingOver if the limit is reached'''

    LOG.debug('Slicing from %s | Keeping %s bytes', offset, 'all' if limit is None else limit)

    if not callable(process):
        raise ValueError('process_output is not callable')

    assert( 
        (isinstance(offset, int) and offset >= 0)
        and
        (limit is None
         or
         (isinstance(limit, int) and limit > 0))
    )

    while True:
        data = yield
        data_len = len(data)

        if data_len < offset: # not enough data to chop off
            offset -= data_len
            continue # ignore output

        if limit is None:
            process(data[offset:])  # no copying here if offset=0!
        else:

            if limit < (data_len - offset): # should stop early
                process(data[offset:limit+offset])
                raise ProcessingOver()
            else:
                process(data[offset:])  # no copying here if offset=0!
                limit -= (data_len - offset)

        offset = 0 # reset offset


def body_decrypt(infile, session_keys, output, offset):
    """Decrypt the whole data portion.

    We fast-forward if offset >= SEGMENT_SIZE.
    We decrypt until the first one occurs:
    * `output` reaches its end
    * `infile` reaches its end."""

    # In this case, we try to fast-forward, and adjust the offset
    if offset >= SEGMENT_SIZE: 
        start_segment, offset = divmod(offset, SEGMENT_SIZE)
        LOG.warning('Fast-forwarding %d segments', start_segment)
        start_ciphersegment = start_segment * CIPHER_SEGMENT_SIZE
        infile.seek(start_ciphersegment, io.SEEK_CUR)  # move forward

    try:
        for ciphersegment in cipher_chunker(infile, CIPHER_SEGMENT_SIZE):
            segment = decrypt_block(ciphersegment, session_keys)
            output.send(segment)
    except ProcessingOver:  # output raised it
        pass


class DecryptedBuffer():
    def __init__(self, fileobj, session_keys, output):
        self.fileobj = fileobj
        self.session_keys = session_keys
        self.buf = io.BytesIO()
        self.block = 0  # just used for printing, if that block is entirely skipped
        self.output = output

    def _append_to_buf(self, data):
        assert( data ), "Why are you adding 'nothing'?"
        oldpos = self.buf.tell()
        self.buf.seek(0, os.SEEK_END)
        self.buf.write(data)
        self.buf.seek(oldpos)

    def buf_size(self):
        oldpos = self.buf.tell()
        self.buf.seek(0, os.SEEK_END)
        size = self.buf.tell() - oldpos
        self.buf.seek(oldpos)
        return size

    def _fetch(self, nodecrypt=False):
        """Populate the internal buffer with data.

        Advances the underlying file object by one cipher chunk.
        Decrypts the bytes only if nodecrypt is False, otherwise, outputs a warning for block entirely skipped.

        Raises ProcessingOver if no more data to pull, so make sure to process the buffer before calling this function.
        """
        LOG.debug('Pulling one segment | Buffer size: %d', self.buf_size())
        data = self.fileobj.read(CIPHER_SEGMENT_SIZE)
        if not data:
            raise ProcessingOver("No more data to read")
        self.block += 1
        if nodecrypt:
            LOG.warning('Block %d is entirely skipped', self.block)
            return
        # else, we decrypt
        LOG.debug('Decrypting block %d', self.block)
        assert( len(data) > CIPHER_DIFF )
        segment = decrypt_block(data, self.session_keys)
        LOG.debug('Adding %d bytes to the buffer', len(segment))
        self._append_to_buf(segment)
        LOG.debug('Buffer size: %d', self.buf_size())
        
    def skip(self, size):
        """Skip size bytes."""
        assert(size > 0)
        LOG.debug('Skipping %d bytes | Buffer size: %d', size, self.buf_size())

        while size > 0:
            # Empty the buffer
            LOG.debug('Left to skip: %d | Buffer size: %d', size, self.buf_size())
            b = self.buf.read(size)
            size -= len(b)
            if size > 0:  # more to skip
                if size > SEGMENT_SIZE:
                    self._fetch(nodecrypt=True)
                    size -= SEGMENT_SIZE
                else:
                    self._fetch(nodecrypt=False)

    def read(self, size):
        """Read size bytes."""
        assert(size > 0)
        LOG.debug('Reading %d bytes | Buffer size: %d', size, self.buf_size())
            
        b = self.buf.read(size)
        if b:
            LOG.debug('Processing %d bytes | Buffer size: %d', len(b), self.buf_size())
            self.output.send(b)
        size -= len(b)

        while size > 0:  # some bytes are missing in the buffer. Go go gadget fetch more blocks
            LOG.debug('Left to read: %d | Buffer size: %d', size, self.buf_size())
            self._fetch(nodecrypt=False)
            b2 = self.buf.read(size)
            if b2:
                LOG.debug('Processing %d bytes | Buffer size: %d', len(b2), self.buf_size())
                self.output.send(b2)
            assert( b2 )
            size -= len(b2)


def body_decrypt_parts(infile, session_keys, output, edit_list=None):
    """Decrypt the data portion according to the edit list.

    We do not decrypt segments that are entirely skipped, and only output a warning (that it should not be the case).
    We decrypt until the end of infile."""

    assert(edit_list is not None), "You can not call this function without an edit_list"
    LOG.debug('Edit List: %s', edit_list)
    assert(len(edit_list) > 0), "You can not call this function without an edit_list"

    decrypted = DecryptedBuffer(infile, session_keys, output)

    try:

        skip = True  # first one is skip
        for edit_length in edit_list:
            # Read/Skip a big chunk
            _apply = decrypted.skip if skip else decrypted.read
            _apply(edit_length)
            # Now flip it and go to the next length
            skip = not skip

        if not skip:
            # We finished the edit list with a skip
            # read now until the end
            while True:
                segment = decrypted.read(SEGMENT_SIZE)

    except ProcessingOver:
        pass


@close_on_broken_pipe
def decrypt(keys, infile, outfile, sender_pubkey=None, offset=0, span=None):
    '''Decrypt infile into outfile, using a given set of keys.

    If sender_pubkey is specified, it verifies the provenance of the header.

    If no header packet is decryptable, it raises a ValueError
    '''
    LOG.info('Decrypting file | Range: [%s, %s[', offset, offset+span+1 if span else 'EOF')

    assert( # Checking the range
        isinstance(offset, int)
        and offset >= 0
        and (
            span is None
            or
            (isinstance(span, int) and span > 0)
        )
    )

    session_keys, edit_list = header.deconstruct(infile, keys, sender_pubkey=sender_pubkey)

    # Infile in now positioned at the beginning of the data portion

    # Generator to slice the output
    output = limited_output(offset=offset, limit=span, process=outfile.write)
    next(output) # start it

    if edit_list is None:
        # No edit list: decrypt all segments until the end
        body_decrypt(infile, session_keys, output, offset)
        # We could use body_decrypt_parts but there is an inner buffer, and segments might not be aligned
    else:
        # Edit list: it drives which segments is decrypted
        body_decrypt_parts(infile, session_keys, output, edit_list=list(edit_list))

    LOG.info('Decryption Over')


##############################################################
##
##    Just reencryption of the header
##
##############################################################


@close_on_broken_pipe
def reencrypt(keys, recipient_keys, infile, outfile, chunk_size=4096, trim=False):
    '''Extract header packets from infile and generate another one to outfile.
    The encrypted data section is only copied from infile to outfile.'''

    # Decrypt and re-encrypt the header
    header_packets = header.parse(infile)
    packets = header.reencrypt(header_packets, keys, recipient_keys, trim=trim)
    outfile.write(header.serialize(packets))

    # Stream the remainder
    LOG.info(f'Streaming the remainder of the file')
    while True:
        data = infile.read(chunk_size)
        if not data:
            break
        outfile.write(data)

    LOG.info('Reencryption Successful')


##############################################################
##
##   Adding or Updating an edit list in the header
##
##############################################################

@close_on_broken_pipe
def rearrange(keys, infile, outfile, offset=0, span=None):
    '''Extract header packets from infile, fetch the edit list if there was,
    and adds/updates it to reflect the [start;end] range.
    The new header is sent to the outfile.
    The encrypted data blocks are only copied from infile to outfile, if the edit list touches them.'''

    # Decrypt and re-encrypt the header
    header_packets = header.parse(infile)

    packets, segment_oracle = header.rearrange(header_packets, keys, offset=offset, span=span)
    outfile.write(header.serialize(packets))

    # Note: The oracle will say True or False, if we should keep a segment
    # And at some point, it will keep saying False forever
    # In other word, the generator never terminate

    # Stream the remainder
    LOG.info('Streaming the remainder of the file')
    chunk_size = SEGMENT_SIZE + CIPHER_DIFF # chunk = cipher segment
    while True:
        segment = infile.read(chunk_size)
        if not segment:
            break
        keep_segment = next(segment_oracle)
        LOG.debug('Keep segment: %s', keep_segment)
        if keep_segment:
            outfile.write(segment)

    del segment_oracle # enough to terminate and remove it?
    LOG.info('Rearrangement Successful')

