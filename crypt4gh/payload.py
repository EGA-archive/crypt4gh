# -*- coding: utf-8 -*-
"""Handle the encryption of the application data."""

import logging
from datetime import datetime
import time

from . import SEGMENT_SIZE, CIPHER_DIFF, CIPHER_SEGMENT_SIZE
from .sodium import (chacha20poly1305_encrypt as segment_encrypt,
                     chacha20poly1305_decrypt as segment_decrypt)

LOG = logging.getLogger(__name__)

def seqnum():
    seqnum_max = 1<<64 # 2^64
    count = yield  # Wait for the start value
    assert count <= seqnum_max
    while True:
        yield count.to_bytes(8,'little') # conversion from int to byte[8] doesn't cost that much, hopefully
        count = count + 1
        if count == seqnum_max:
            count = 0

def no_aead():
    while True:
        yield None

##############################################################
##
##    Symmetric encryption - Chacha20_Poly1305, with/without AEAD
##
##############################################################

def encrypt(infile, outfile, session_key, start):

    if start is not None:
        snum = seqnum()
        next(snum) # start it
        snum.send(start)
    else:
        snum = no_aead()

    segment = bytearray(SEGMENT_SIZE)
    ciphersegment = bytearray(CIPHER_SEGMENT_SIZE)

    LOG.debug('Encrypting Crypt4GH payload (seqnum start: %s)', start)

    while True:

        dlen = infile.readinto(segment)
        if dlen == 0: # no more data
            if start is not None: # one more "empty" segment
                clen = segment_encrypt(ciphersegment, b'', session_key, next(snum))
                outfile.write(ciphersegment[:clen])
            break

        clen = segment_encrypt(ciphersegment, segment[:dlen], session_key, next(snum))
        outfile.write(ciphersegment[:clen])

        if dlen < SEGMENT_SIZE: # not a full segment
            break

    LOG.info('Encryption Successful')

##############################################################
##
##    Symmetric decryption - Chacha20_Poly1305, with/without AEAD
#
##############################################################

def _decrypt(infile, outfile, session_keys, version=1):
    """Decrypt the whole data portion."""

    LOG.info('Starting Decryption')

    keys = []

    for method, key, start in session_keys:
        if method == 1:
            snum = seqnum()
            next(snum) # start it
            snum.send(start)
        else:
            snum = no_aead()
        keys.append( (key, snum) )

    segment = bytearray(SEGMENT_SIZE)
    ciphersegment = bytearray(CIPHER_SEGMENT_SIZE)
    plen = 0

    while True:
        clen = infile.readinto(ciphersegment)
        if clen == 0:
            if version == 2 and plen == SEGMENT_SIZE: # plen != 0:
                raise ValueError('Missing final segment (for version 2)')
            break # no more data
        assert( clen >= CIPHER_DIFF )

        # trying all keys
        for key, snum in keys:
            try:
                plen = segment_decrypt(segment, ciphersegment[:clen], key, next(snum))
                break # it worked
            except Exception as e:
                LOG.error('Decryption failed: %s', e)
        else: # no keys worked: Bark!
            raise ValueError('Could not decrypt that block')

        outfile.write(segment[:plen])
        
        if plen < SEGMENT_SIZE:
            break # no a full segment, or final segment

    LOG.info('Decryption Successful')


##############################################################
##
##    Edit list helper
#
##############################################################

class ProcessingOver(Exception):
    pass

class LimitedOutput():

    __slots__ = ('outfile',
                 'edit_list',
                 'length',
                 'skip')

    def __init__(self, outfile, edit_list):
        assert edit_list, "Missing edit list"
        self.outfile = outfile
        self.edit_list = edit_list # generator
        self.length = next(self.edit_list)
        self.skip = True # first is a skip
        LOG.debug('has edit list')

    def next_length(self):
        self.skip = not self.skip # flip it
        try:
            self.length = next(self.edit_list)
        except StopIteration:
            self.length = None

    def write(self, data):
        
        while True:

            if not data:
                break

            dlen = len(data)
            
            # LOG.debug('Length: %s | Skip: %s | dlen: %d', self.length, self.skip, dlen)

            if self.length is None or self.length >= dlen:
                #  |---------------|
                #                       ^ length
                #                  ^ dlen
                if not self.skip:
                    self.outfile.write(data)

                if self.length is not None:
                    self.length -= dlen
                    if self.length == 0:
                        self.next_length()
                else:
                    if self.skip: # skip until the end
                        raise ProcessingOver() # => stop here

                break

            #  |---------------|
            #         ^ length
            #                  ^ dlen
            if not self.skip:
                self.outfile.write(data[:self.length])

            data = data[self.length:]
            self.next_length()

            if self.skip and self.length is None: # skip until the end
                raise ProcessingOver()            # => stop here



def decrypt(infile, outfile,
            session_keys, edit_list,
            version=1):

    if edit_list is None:
        return _decrypt(infile, outfile, session_keys, version=version)

    _outfile = LimitedOutput(outfile, edit_list)
    try:
        return _decrypt(infile, _outfile, session_keys, version=version)
    except ProcessingOver:
        LOG.info('Decryption Successful (stopped with edit list)')



##############################################################
##
##    Fast Copy helper
#
##############################################################

def copy(infile, outfile, chunksize):

    LOG.debug('Buffer copy: %s bytes', chunksize)
    # Localize variable access to minimize overhead.
    in_read = infile.read
    out_write = outfile.write
    while buf := in_read(chunksize):
        out_write(buf)


# import os
# import posix
# import errno
# import shutil

# def fastcopy(fsrc, fdst, chunksize):

#     # adapted from https://github.com/python/cpython/blob/3.13/Lib/shutil.py

#     try:

#         # macOS
#         if shutil._HAS_FCOPYFILE:
#             LOG.debug('Trying shutil._fastcopy_fcopyfile')
#             shutil._fastcopy_fcopyfile(fsrc, fdst, posix._COPYFILE_DATA)
#             return
#         # Linux
#         elif shutil._USE_CP_SENDFILE:
#             LOG.debug('Trying shutil._fastcopy_sendfile')
#             shutil._fastcopy_sendfile(fsrc, fdst)
#             return
#         # Windows, see:
#         elif shutil._WINDOWS:
#             LOG.debug('Windows plateform')
#             try:
#                 src_filesize = os.fstat(fsrc.fileno()).st_size
#             except OSError:
#                 src_filesize = None
#             if src_filesize:
#                 LOG.debug('Trying shutil._copyfileobj_readinto')
#                 shutil._copyfileobj_readinto(fsrc, fdst, min(src_filesize, shutil.COPY_BUFSIZE))
#                 return

#         raise ValueError('No Fast-Copy')

#     except shutil._GiveupOnFastCopy as e:
#         LOG.error('Fast-Copy error: %s', e)
#         raise ValueError('Fast-Copy failed')



# # def fastcopy(source_fd, target_fd, chunksize):

# #     LOG.debug('Chunk size: %s', chunksize)

# #     # Use OS fast copy where available.
# #     if hasattr(posix, '_fcopyfile'):
# #         LOG.debug('Trying posix fcopyfile')
# #         try:
# #             out = posix._fcopyfile(source_fd, target_fd, posix._COPYFILE_DATA)
# #             LOG.debug('Output: %s', out)
# #             return
# #         except OSError as e:
# #             LOG.error('posix._fcopyfile: %r', e)
# #             if e.errno not in (errno.EINVAL, errno.ENOTSUP):
# #                 raise

# #     if hasattr(os, '_copy_file_range'): 
# #         LOG.debug('Trying os copy_file_range')
# #         try:
# #             out = os._copy_file_range(source_fd, target_fd)
# #             LOG.debug('Output: %s', out)
# #             return
# #         except OSError as e: 
# #             LOG.error('os._copy_file_range: %r', e)
# #             if e.errno not in (errno.ETXTBSY, errno.EXDEV):
# #                 raise
            
# #     if hasattr(os, '_sendfile'): 
# #         LOG.debug('Trying os sendfile')
# #         try:
# #             out = os._sendfile(source_fd, target_fd)
# #             LOG.debug('Output: %s', out)
# #             return
# #         except OSError as e:
# #             LOG.error('os._sendfile: %r', e)
# #             if e.errno != errno.ENOTSOCK:
# #                 raise

# #     if hasattr(os, 'splice'): 
# #         try:
# #             while os.splice(source_fd, target_fd, chunksize, flags=os.SPLICE_F_MOVE | os.SPLICE_F_MORE):
# #                 pass
# #             return
# #         except OSError as e:
# #             LOG.error('os.splice: %r', e)
# #             if e.errno not in (errno.EINVAL, errno.ENOTSUP, errno.EXDEV):
# #                 raise

# #     raise ValueError('Fast-Copy failed')
