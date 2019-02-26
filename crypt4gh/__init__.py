# -*- coding: utf-8 -*-

"""The crypt4gh package is an implementation to handle the GA4GH
cryptographic file format."""


__title__ = 'GA4GH cryptographic utilities'
__version__ = VERSION = 1
__author__ = 'Frédéric Haziza <frederic.haziza@crg.eu>'
__license__ = 'Apache License 2.0'
__copyright__ = __title__ + ' @ CRG'

PROG = 'crypt4gh'

import sys
import logging
LOG = logging.getLogger(__name__)

##############################################################
##
##    Decorator for Error Handling
##
##############################################################
import errno
from nacl.exceptions import InvalidkeyError, BadSignatureError, CryptoError
from cryptography.exceptions import InvalidTag

def convert_error(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (InvalidkeyError, BadSignatureError, CryptoError) as e:
            LOG.error('Converting Crypto errors')
            raise ValueError('Crypt4GH Crypto Error') from e
    return wrapper

def close_on_broken_pipe(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (IOError) as e:
            if e.errno == errno.EPIPE:
                LOG.error('Closing on Broken Pipe')
            # raise ValueError(f'Crypt4GH Error: {e}') from e
    return wrapper

def exit_on_invalid_passphrase(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (InvalidTag) as e:
            LOG.error('Exiting for %r', e)
            LOG.error('Invalid Key or Passphrase', file=sys.stderr)
            sys.exit(2)
    return wrapper
