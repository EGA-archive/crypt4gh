Usage & Examples
================

.. highlight:: shell

The usual ``-h`` flag shows you the different options that the tool accepts.

.. code-block:: console

    $ crypt4gh -h
    LocalEGA utilities for the cryptographic GA4GH standard.
    Reads from stdin and Outputs to stdout

    Usage:
		crypt4gh [-hv] [--log <file>] encrypt [--signing_key <file>] [--pk <path>]
		crypt4gh [-hv] [--log <file>] decrypt [--sk <path>]
		crypt4gh [-hv] [--log <file>] reencrypt [--signing_key <file>] [--sk <path>] [--pk <path>]
		crypt4gh [-hv] [--log <file>] generate [-f <path>] [-P <passphrase>] [--signing]
	
    Options:
		-h, --help             Prints this help and exit
		-v, --version          Prints the version and exits
		--log <file>           Path to the logger file (in YML format)
		--pk <keyfile>         Public Curve25519 key to be used for encryption
		--sk <keyfile>         Private Curve25519 key to be used for decryption
		--signing_key <file>   Ed25519 Signing key for the header
		-f <path>              Private Curve25519 key (.pub is appended for the Public one) [default: ~/.lega/ega.key]
		-P <passphrase>        Passphrase to lock the secret key [default: None]
		--signing              Generate an ed25519 signing/verifying keypair

    Environment variables:
		C4GH_LOG         If defined, it will be used as the default logger
		C4GH_PUBLIC_KEY  If defined, it will be used as the default public key (ie --pk ${C4GH_PUBLIC_KEY})
		C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${C4GH_SECRET_KEY})
		C4GH_SIGNING_KEY If defined, it will be used as the default signing key (ie --signing_key ${C4GH_SIGNING_KEY})

Examples
--------

If one wants to encrypt a file, say, for the Swedish Local EGA instance:

.. code-block:: console

    $ crypt4gh encrypt --pk path_to_pubkey < inputfile > outputfile

