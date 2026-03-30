Usage
=====

.. highlight:: shell

The usual ``-h`` flag shows you the different options that the tool accepts.

.. code-block:: console

    $ crypt4gh -h

   Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.

   Usage:
	crypt4gh [-hv] [--log <file>] encrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--range <start-end>] [--header <path>]
        crypt4gh [-hv] [--log <file>] decrypt [--sk <path>] [--sender_pk <path>] [--range <start-end>]
        crypt4gh [-hv] [--log <file>] rearrange [--sk <path>] --range <start-end>
        crypt4gh [-hv] [--log <file>] reencrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--trim] [--header-only]

   Options:
        -h, --help             Prints this help and exit
        -v, --version          Prints the version and exits
        --log <file>           Path to the logger file (in YML format)
        --sk <keyfile>         Curve25519-based Private key
                               When encrypting, if neither the private key nor C4GH_SECRET_KEY are specified, we generate a new key 
        --recipient_pk <path>  Recipient's Curve25519-based Public key
        --sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (akin to signature)
        --range <start-end>    Byte-range either as  <start-end> or just <start> (Start included, End excluded)
        -t, --trim             Keep only header packets that you can decrypt
        --header <path>        Where to write the header (default: stdout)
        --header-only          Whether the input data consists only of a header (default: false)

   Environment variables:
        C4GH_LOG         If defined, it will be used as the default logger
        C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${{C4GH_SECRET_KEY}})
        C4GH_PASSPHRASE  If defined, it will be used as the passphrase
                         for decoding the secret key, replacing the callback.
                         Note: this is insecure.
        C4GH_DEBUG       If True, it will print (a lot of) debug information.
                         Note: the output might contain secrets
