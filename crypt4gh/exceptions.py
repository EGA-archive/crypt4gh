##############################################################
##
##    Decorator for Error Handling
##
##############################################################

import sys
import logging
import errno

LOG = logging.getLogger(__name__)


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
        except Exception as e:
            LOG.error('Exiting for %r', e)
            print('Invalid Key or Passphrase', file=sys.stderr)
            sys.exit(2)
    return wrapper
