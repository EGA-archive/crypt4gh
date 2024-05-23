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

Storing the encrypted header separately
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The encrypted header can be stored separately from the encrypted data. This is useful, for example, when sharing the encrypted message with many recipients. In this case, only the header needs to be re-encrypted (for a specific recipient) while the encrypted data can stay the same.

To store the encrypted header in a separate file ``header.dat``, use the flag ``--header``:

.. code-block:: console

    $ crypt4gh encrypt --sk alice.sec --recipient_pk bob.pub --header header.bob.c4gh < M > M.data.c4gh

Bob can then decrypt the message by concatenating the header and the data, and decrypting the whole file:

.. code-block:: console

    $ cat header.bob.c4gh M.data.c4gh | crypt4gh decrypt --sk bob.sec > M

To re-encrypt the message for another user Eve, with public key ``eve.pub``, Alice can run the ``crypt4gh reencrypt`` command: 

.. code-block:: console

    $ crypt4gh reencrypt --sk alice.sec --recipient_pk eve.pub < header.alice.c4gh > header.eve.c4gh
