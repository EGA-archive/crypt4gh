Installation
============

.. highlight:: shell

The sources for EGA cryptor can be downloaded and installed from the `EGA-archive Github repo`_.

.. code-block:: console

    pip install crypt4gh

or using:

.. code-block:: console

    git clone https://github.com/EGA-archive/crypt4gh
    pip install -r crypt4gh/requirements.txt
    pip install ./crypt4gh
    #
    # or just
    #
    pip install git+https://github.com/EGA-archive/crypt4gh.git



.. _EGA-archive Github repo: https://github.com/EGA-archive/crypt4gh


----

You can run a few tests after you installed the python package (and its dependencies).
We provide a testsuite simulating, for example, that Bob encrypts a randomly-generated file for Alice and Alice decrypts it.
We use `BATS <https://github.com/bats-core/bats-core>`_ to run the testsuite (so... first install it).

.. code-block:: console

    git clone https://github.com/EGA-archive/crypt4gh
    pip install -r crypt4gh/requirements.txt
    bats crypt4gh/tests

which should output, something along those lines (yes, the testsuite might grow):

.. code-block:: console

   ✓ Bob sends a secret (random) 10MB file to Alice
   ✓ Bob sends the testfile secretly to Alice
   ✓ Bob encrypts the testfile for himself and reencrypts it for Alice
   ✓ Bob sends only the Bs from the testfile secretly to Alice
   ✓ Bob sends one A, all Bs, one C, from the testfile secretly to Alice
   ✓ Bob rearranges the encrypted testfile to send one A, all Bs, one C, to Alice
   ✓ Bob sends only the Bs from the testfile secretly to Alice
   ✓ Bob sends one A, all Bs, one C, from the testfile secretly to Alice
   ✓ Bob rearranges the encrypted testfile to send one A, all Bs, one C, to Alice
   
   10 tests, 0 failures
