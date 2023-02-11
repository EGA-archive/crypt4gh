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
# Reencrypt has the option to "trim" the headers.
# That means, we toss away the packets that we can't decrypt, since they are targeting another user.


__title__ = 'GA4GH cryptographic utilities'
__version__ = '2.0' # VERSION in header is 2 (as 4 bytes little endian)
__author__ = 'Frédéric Haziza'
__author_email__ = 'frederic.haziza@crg.eu'
__license__ = 'Apache License 2.0'
__copyright__ = __title__ + ' @ CRG'

PROG = 'crypt4gh'

import sys
import logging
LOG = logging.getLogger(__name__)

# For this verion: Data blocks are bounded to that specific size
#                  and there is no edit list
VERSION = 2
SEGMENT_SIZE = 65536



