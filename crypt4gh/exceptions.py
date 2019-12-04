##############################################################
##
##    Decorator for Error Handling
##
##############################################################

import sys
import logging
import errno

from nacl.exceptions import (InvalidkeyError,
                             BadSignatureError,
                             CryptoError)

LOG = logging.getLogger(__name__)

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
        except CryptoError as e:
            LOG.error('Exiting for %r', e)
            print('Invalid Key or Passphrase', file=sys.stderr)
            sys.exit(2)
    return wrapper
