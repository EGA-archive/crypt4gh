Usage & Examples
================

.. highlight:: shell

The usual ``-h`` flag shows you the different options that the tool accepts.

.. code-block:: console

    $ crypt4gh -h

    Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.

    Usage:
	crypt4gh [-hv] [--log <file>] encrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--range <start-end>]
	crypt4gh [-hv] [--log <file>] decrypt [--sk <path>] [--sender_pk <path>] [--range <start-end>]
	crypt4gh [-hv] [--log <file>] rearrange [--sk <path>] --range <start-end>
	crypt4gh [-hv] [--log <file>] reencrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--trim]

    Options:
	-h, --help             Prints this help and exit
	-v, --version          Prints the version and exits
	--log <file>           Path to the logger file (in YML format)
	--sk <keyfile>         Curve25519-based Private key
	                       When encrypting, if neither the private key nor C4GH_SECRET_KEY are specified, we generate a new key 
	--recipient_pk <path>  Recipient's Curve25519-based Public key
	--sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (aka, signature)
	--range <start-end>    Byte-range either as  <start-end> or just <start> (Start included, End excluded)
	-t, --trim             Keep only header packets that you can decrypt


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

    $ crypt4gh-keygen --sk user.sec --pk user.pub

The private key will be encrypted with a passphrase. The user is prompted at the terminal for that passphrase.
