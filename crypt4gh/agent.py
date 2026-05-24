"""
SSH Agent interface

See https://tools.ietf.org/html/draft-miller-ssh-agent-02#section-4.4
for the request/response structure from the agent.

See http://www.unixwiz.net/techtips/ssh-agent-forwarding.html
for an explantion about the ssh-agent (signing the challenge)
"""

import os
import socket
import struct
import sys
import io
import logging
import hashlib
import base64

from crypt4gh import sodium

LOG = logging.getLogger(__name__)

REQUEST_SSH_AGENT_IDENTITIES = struct.pack(">I", 1) + struct.pack("B", 11) # uint32 + byte
RESPONSE_SSH_AGENT_IDENTITIES = struct.pack("B", 12)
SSH_AGENTC_SIGN_REQUEST = struct.pack("B", 13)

SSH_AGENT_FAILURE = 5

conn = None

def init_connect():
    global conn
    # Let it raise the connection errors
    ssh_auth_sock = os.getenv("SSH_AUTH_SOCK")

    if ssh_auth_sock and (sys.platform != "win32"):
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.connect(ssh_auth_sock)
        return # all good
    elif sys.platform == "win32":
        from . import win_pageant
        if win_pageant.can_talk_to_agent():
            conn = win_pageant.PageantConnection()
            return
    raise ValueError('SSH Agent not reachable')

def close():
    """Close the SSH agent connection."""
    global conn
    if conn is not None:
        conn.close()
        conn = None

def _consume_cstring(stream):
    blob_length = struct.unpack(">I", stream.read(4))[0]
    blob = stream.read(blob_length)
    if len(blob) != blob_length:
        raise ValueError("stream too short")
    return blob

def _get_response(request):
    assert(conn)
    conn.send(request)
    data = conn.recv(4)
    if len(data) < 4:
        raise ValueError("SSH Agent connection lost")
    response_length = struct.unpack(">I", data)[0]

    response = conn.recv(response_length)
    while len(response) < response_length:
        extra = conn.recv(response_length - len(response))
        if len(extra) == 0:
            raise ValueError("SSH Agent connection lost")
        response += extra
    return io.BytesIO(response)

def get_keys( types=None, names=None ):
    """
    Iterate through the list of keys available through the SSH agent, if any.
    We only return the ED25519 keys
    Yields a tuple (comment, blob)
    """
    global conn
    if conn is None:
        init_connect()

    # We have a connection
    response = _get_response(REQUEST_SSH_AGENT_IDENTITIES)

    # response should be:
    # one byte: SSH_AGENT_IDENTITIES_ANSWER
    # 4 big endian byte:  nkeys
    if response.read(1) != RESPONSE_SSH_AGENT_IDENTITIES:
        raise ValueError("could not get keys from ssh-agent")
    nkeys = struct.unpack(">I", response.read(4))[0]

    # For each key: 4 bytes + blob + 4bytes + comment
    for i in range(nkeys):
        blob = _consume_cstring(response)
        # blob = keytype + private key material
        blob = io.BytesIO(blob)
        key_type = _consume_cstring(blob).decode()
        key_material = _consume_cstring(blob)
        comment = _consume_cstring(response).decode()

        if key_type != 'ssh-ed25519':
            LOG.debug('Ignoring %s key for %s', key_type, comment)
            continue

        if names and comment not in names:
            continue
        yield (comment, key_material)


if __name__ == '__main__':

    for comment, key in get_keys():
        k = sodium.derive_pk(key)

        sha256 = hashlib.sha256()
        sha256.update(k)
        print(f'{comment:>16}: sha256 ', sha256.hexdigest())

        fingerprint = base64.b64encode(sha256.digest()).decode().replace('=','')
        print(f'{comment:>16}:', fingerprint)
