import sys
assert sys.version_info >= (3, 6), "This tool requires python version 3.6 or higher"

import os
import io
import logging
from base64 import b64decode

from . import ssh, c4gh

LOG = logging.getLogger(__name__)

#######################################################################
## Loading
#######################################################################


def load_from_pem(filepath):
    with open(filepath, 'rb') as f:
        lines = []

        # Strip empty lines and newline characters
        for l in f.readlines():
            l = l.strip()
            if l:
                lines.append(l)

        if (not lines
            or not lines[0].startswith(b'-----BEGIN ')
            or not lines[-1].startswith(b'-----END ')
            ):
            raise ValueError('Not a PEM format')

        return b64decode(b''.join(lines[1:-1]))

def get_public_key(filepath):
    '''Read the public key from keyfile location.'''

    with open(filepath, 'rb') as f:
        lines = []

        # Strip empty lines and newline characters
        for l in f.readlines():
            l = l.strip()
            if l:
                lines.append(l)

        if not lines:
            raise ValueError('Empty key')

        line = lines[0]

        if b'CRYPT4GH' in line: # it's Crypt4GH key
            LOG.info('Loading a Crypt4GH public key')
            return b64decode(b''.join(lines[1:-1]))

        if line[:4] == b'ssh-': # It's an SSH key
            LOG.info('Loading an OpenSSH public key')
            return ssh.get_public_key(line)

    raise NotImplementedError('Unsupported key format')


def get_private_key(filepath, callback):
    '''Read the private key from keyfile location.

    If the private key is encrypted, the user will be prompted for the passphrase.
    '''
    data = load_from_pem(filepath)
    stream = io.BytesIO(data)
    magic_word = stream.read(len(c4gh.MAGIC_WORD)) # start with C4GH, it's smaller

    if magic_word == c4gh.MAGIC_WORD: # It's a Crypt4GH key
        LOG.info('Loading a Crypt4GH private key')
        return c4gh.parse_private_key(stream, callback)

    magic_word += stream.read(len(ssh.MAGIC_WORD)-len(c4gh.MAGIC_WORD))
    if magic_word == ssh.MAGIC_WORD: # It's an SSH key
        LOG.info('Loading an OpenSSH private key')
        return ssh.parse_private_key(stream, callback)[0] # we also return the pubkey
    
    raise ValueError('Invalid key format')
