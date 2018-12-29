======================
Crypt4GH utility
======================

Bob wants to send a message to Alice, containing sensitive data. Bob
uses `crypt4gh`, a tool to encrypt, decrypt or re-encrypt files
according to the :download:`GA4GH encryption file format
<./static/crypt4gh.pdf>`.

Alice and Bob generate both a pair of public/private keys.

.. code-block:: console

   crypt4gh generate --sk alice.sec --pk alice.pub
   crypt4gh generate --sk bob.sec --pk bob.pub


Bob encrypts a file for Alice:

.. code-block:: console

   $ crypt4gh encrypt --sk bob.sec --recipient_pk alice.pub < file > file.c4gh

Alice decrypts the encrypted file:

.. code-block:: console

   $ crypt4gh decrypt --sk alice.sec < file.c4gh


.. image:: https://asciinema.org/a/JtctM4ATUBpGM3oQqbQ2Sr6B4.png
   :target: https://asciinema.org/a/JtctM4ATUBpGM3oQqbQ2Sr6B4
   :alt: Demo


Table of Contents
=================

.. toctree::
   :maxdepth: 1
   :name: toc

   Installation         <setup>
   Encryption           <encryption>
   Key Format           <keys>
   Usage & Examples     <usage>
   Python Modules       <code>


|Travis| | Version |version| | Generated |today|


.. |Travis| image:: https://travis-ci.org/EGA-archive/crypt4gh.svg?branch=master
	:alt: Build Status
	:class: inline-baseline

.. |moreabout| unicode:: U+261E .. right pointing finger
.. |connect| unicode:: U+21cc .. <-_>
