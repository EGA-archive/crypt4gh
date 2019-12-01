# -*- coding: utf-8 -*-

"""The crypt4gh package is an implementation to handle the GA4GH
cryptographic file format."""

# -----------------------------------
# Implementation Notes:
# -----------------------------------
#
# We make the following choices for this utility.
#
# Even though the library can encrypt/decrypt/reencrypt for multiple users, and use multiple session keys,
# the command-line options allow only one recipient (ie --recipient_sk can not be repeated)
# and only one writer/sender. The code creates only one session key when encrypting a stream.
# This simplifies the code
#
# We do separate 'rearrange' from 'reencrypt', to make it simpler.
# If you want to combine them, pipe one into the other.
#
# Reencrypt has the option to "trim" the headers.
# That means, we toss away the packets that we can't decrypt, since they are targeting another user.
#
# Rearrange does not have that option, as changing the edit list packet for the current user might
# result in the data section not containing the same blocks.
#
# We make the choice that you can only use one range (ie, option not repeatable).
#
# Knowing that the range <start-end> is applied to the "decrypted file" (ie the original content, as if no encryption was applied),
# we have the two following cases:
# - there is no Edit List: we fast-forward to the relevant cipher block (as <start-end> states).
# - there is an Edit List: we reject the file if a cipher block is entirely skipped (independantly of the <start-end> range).
# (If edit list and range are both used: we decipher each block and then apply the range)
#
#
# Finally, we do not yet implement slicing a file that already contains an Edit List
#


__title__ = 'GA4GH cryptographic utilities'
__version__ = '1.1' # VERSION in header is 1 (as 4 bytes little endian)
__author__ = 'Frédéric Haziza'
__author_email__ = 'frederic.haziza@crg.eu'
__license__ = 'Apache License 2.0'
__copyright__ = __title__ + ' @ CRG'

PROG = 'crypt4gh'

import sys
import logging
LOG = logging.getLogger(__name__)

# For this verion: Data blocks are bounded to that specific size
VERSION = 1
SEGMENT_SIZE = 65536



