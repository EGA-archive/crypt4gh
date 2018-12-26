Usage & Examples
================

.. highlight:: shell

The usual ``-h`` flag shows you the different options that the tool accepts.

.. code-block:: console

    $ crypt4gh -h

    Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.

    Usage:
    crypt4gh [-hv] [--log <file>] encrypt [--sk <path>] --recipient_pk <path>
    crypt4gh [-hv] [--log <file>] decrypt [--sk <path>] [--sender_pk <path>]
    crypt4gh [-hv] [--log <file>] reencrypt [--sk <path>] --recipient_pk <path> [--sender_public_key <path>]
    crypt4gh [-hv] [--log <file>] generate [-f] [--pk <path>] [--sk <path>] [--nocrypt] [-C <comment>] [-R <rounds>]
    
    Options:
    -h, --help             Prints this help and exit
    -v, --version          Prints the version and exits
    --log <file>           Path to the logger file (in YML format)
    --sk <keyfile>         Curve25519-based Private key [default: ~/.c4gh/key]
    --pk <keyfile>         Curve25519-based Public key  [default: ~/.c4gh/key.pub]
    --recipient_pk <path>  Recipient's Curve25519-based Public key
    --sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (aka, signature)
    -C <comment>           Key's Comment
    --nocrypt              Do not encrypt the private key.
    Otherwise it is encrypted in the Crypt4GH key format
    -R <rounds>            Numbers of rounds for the key derivation. Ignore it to use the defaults.
    -f                     Overwrite the destination files

    Environment variables:
	C4GH_LOG         If defined, it will be used as the default logger
	C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${C4GH_SECRET_KEY})

Examples
--------

Assume Alice, with public/private key alice.pub and alice.sec respectively, wants to send a message to Bob, with public/private key bob.pub and bob.sec respectively.

Alice can encrypt the message M with:

.. code-block:: console

    $ crypt4gh encrypt --sk alice.sec --recipient_pk bob.pub < M > M.c4gh

Bob can decrypt the encrypted message with:

.. code-block:: console

    $ crypt4gh decrypt --sk bob.sec < M.c4gh > M

If Bob wants to, optionally, verify that the message indeed comes from Alice, he needs to fetch Alice's public key via another trusted channel. He can then decrypt *and* check the provenance of the file with:

.. code-block:: console

    $ crypt4gh decrypt --sk bob.sec --sender_pk alice.pub < M.c4gh > M

Any user can generate a keypair with:

.. code-block:: console

    $ crypt4gh generate --sk user.sec --pk user.pub

The private key will be encrypted with a passphrase. The user is prompted at the terminal for that passphrase.
