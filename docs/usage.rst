Usage & Examples
================

.. highlight:: shell

The usual ``-h`` flag shows you the different options that the tool accepts.

.. code-block:: console

    $ lega-cryptor -h
    LocalEGA utilities for the cryptographic GA4GH standard.

    Usage:
       lega-cryptor [-hv] [--log <file>] list [-s <URL> | -p <path>]
       lega-cryptor [-hv] [--log <file>] encrypt [-r <recipient>] -s <URL> [-i <input>] [-o <output>]
       lega-cryptor [-hv] [--log <file>] encrypt [-r <recipient>] [-p <path>] [-i <input>] [-o <output>]
       lega-cryptor [-hv] [--log <file>] encrypt --pk <path> [-i <input>] [-o <output>]
       lega-cryptor [-hv] [--log <file>] decrypt --sk <path> [-i <input>] [-o <output>]
       lega-cryptor [-hv] [--log <file>] reencrypt --sk <path> --pk <path> [-i <input>] [-o <output>]
       lega-cryptor [-hv] [--log <file>] reencrypt --server <url> --keyid <secret> [-i <input>] [-o <output>]

    Options:
       -h, --help             Prints this help and exit
       -v, --version          Prints the version and exits
       --log <file>           Path to the logger file (in YML format)
       -s <URL>, --server <URL>
                              Lists information about all keys in the keyserver
       -p <file>, --pubring <file>
                              Lists information about all keys in the pubring.
                              If not specified, a default pubring is used either from the
                              LEGA_PUBRING environment variable (if it exists) or as the one
                              supplied within this package.
       -r RECIPIENT           Encrypt for the given recipient [default: ega@crg.eu]
       --pk <keyfile>         Public PGP key to be used for encryption
       --sk <keyfile>         Private PGP key to be used for decryption
       --keyid <id>           Key ID used to retrieve the key material from the keyserver
       -i <file>, --input <file>
                              Input file. If not specified, it uses stdin
       -o <file>, --output <file>
                              Output file.  If not specified, it uses stdout

    Environment variables:
       LEGA_LOG       If defined, it will be used as the default logger
       LEGA_PUBRING   If defined, it will be used as the default pubring


Finding which public key to use
-------------------------------

.. code-block:: console

    $ lega-cryptor list
    Available keys from [path redacted]/legacryptor/pubring.bin
    ╔══════════════════╦════════════════╦═════════════════════╦════════════════════════════════════════╗
    ║ Key ID           ║ User Name      ║ User Email          ║ User Comment                           ║
    ╠══════════════════╬════════════════╬═════════════════════╬════════════════════════════════════════╣
    ║ 783A1FDBD9899BBA ║ EGA Sweden     ║ ega@nbis.se         ║ @NBIS                                  ║
    ║ F57E35FE22290D3A ║ EGA Finland    ║ ega@csc.fi          ║ @CSC                                   ║
    ║ 3D214775952B5529 ║ EGA_Public_key ║ ega-admin@ebi.ac.uk ║ Public key protected with a passphrase ║
    ║ 6148E9185EB5F733 ║ EGA CRG        ║ ega@crg.eu          ║ @CRG                                   ║
    ╚══════════════════╩════════════════╩═════════════════════╩════════════════════════════════════════╝
    The first substring that matches the requested recipient will be used as the encryption key
    Alternatively, you can use the KeyID itself


.. note:: The hereabove output might differ from your output. The associated public keyring is just used for the demo.

Creating a Custom Public Keyring
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In order to create a custom Public keyring in a custom `/path` one can make use of:

.. code-block:: console

    gpg --no-default-keyring --keyring /path/pubring.bin --import /path/key.pub

Repeat the process for multiple keys.

Examples
--------

If one wants to encrypt a file, say, for the Swedish Local EGA instance:

.. code-block:: console

    $ lega-cryptor encrypt -r Sweden < inputfile > outputfile


or equivalently,

.. code-block:: console

    $ lega-cryptor encrypt -r nbis.se < inputfile > outputfile
    $ lega-cryptor encrypt -r 783A1FDBD9899BBA < inputfile > outputfile
    $ lega-cryptor encrypt -r Sweden -i inputfile -o outputfile
