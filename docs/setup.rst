Installation
============

.. highlight:: shell

The sources for EGA cryptor can be downloaded and installed from the `EGA-archive Github repo`_.

.. code-block:: console

    pip install crypt4gh

or compile/install it from sources:

.. code-block:: console

    git clone --recursive https://github.com/EGA-archive/crypt4gh
    pip install -r crypt4gh/requirements.txt
    pip install ./crypt4gh


The above will use a version of `libsodium`_ bundled in the repository as a submodule (hence cloning with ``--recursive``).
You have the possibility to use the version of libsodium already installed on your system.
For that, you set the following environment variables before running ``pip install``.

.. code-block:: console

    export SODIUM_INSTALL=system

    # If libsodium is not installed in default locations,
    # you need to adjust CFLAGS and LDFLAGS:
    export CFLAGS="-I/path/to/libsodium/include"
    export LDFLAGS="-L/path/to/libsodium/lib -lsodium"
    
    # For example, using pkg-config
    export CFLAGS="$(pkg-config --cflags libsodium)"
    export LDFLAGS="$(pkg-config --libs libsodium)"                    # on macos
    export LDFLAGS="-Wl,--no-as-needed $(pkg-config --libs libsodium)" # on linux

    # and finally:
    pip install ./crypt4gh


.. note::

   The compiler on macOS is more agressive and restricts the compilation to only the functions it uses from libsodium. This creates a smaller **crypt4gh** module.

   On Linux, it is more conservative and keeps *all* libsodium functions, and therefore produces a bigger module. It seems that you also need to pass ``-Wl,--no-as-needed``, on Linux, to the linker (ie add it in LDFLAGS) to resolve symbols in the python module.

   Help me out if you know how to resolve that.



.. _EGA-archive Github repo: https://github.com/EGA-archive/crypt4gh
.. _libsodium: https://libsodium.org


----

Tests
=====

You can run a few tests after installation.
We provide a testsuite simulating, for example, that Bob encrypts a randomly-generated file for Alice and Alice decrypts it.
We use `BATS <https://github.com/bats-core/bats-core>`_ to run the testsuite (so... install bats first).

.. code-block:: console

    cd [path/to/crypt4gh/cloned/repository]
    bats tests

which should output, something along those lines (yes, the testsuite might grow):

.. code-block:: console

   ✓ Bob sends a secret message to Alice, buried in some random data

   ✓ Bob sends a secret (random) 10MB file to Alice
   ✓ Bob sends the testfile secretly to Alice
   ✓ Bob encrypts the testfile for himself and reencrypts it for Alice
   ✓ Bob sends a secret (random) 10MB file to Alice, without his key

   ✓ Bob sends the testfile secretly (with separate header and data) to Alice
   ✓ Bob encrypts the testfile for himself (with separate header) and reencrypts the header for Alice

   ✓ Bob sends a secret (random) 10MB file to Alice, using his ssh-key
   ✓ Bob sends a secret (random) 10MB file to Alice, using Alice's ssh-key
   ✓ Bob sends a secret (random) 10MB file to Alice, both using their ssh-keys

   ✓ Bob sends the testfile secretly to himself and Alice
   ✓ Bob encrypts the testfile for himself and reencrypts it for himself and Alice

   ✓ Bob sends only the Bs from the testfile secretly to Alice
   ✓ Bob sends one A, all Bs, one C, from the testfile secretly to Alice
   ✓ Bob rearranges the encrypted testfile to send one A, all Bs, one C, to Alice

   15 tests, 0 failures
