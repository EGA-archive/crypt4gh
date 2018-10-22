======================
LocalEGA GA4GH cryptor
======================

`crypt4gh` is a tool to encrypt, decrypt or re-encrypt files
according to the  :download:`GA4GH encryption file format
<./static/crypt4gh.pdf>`.

Demonstration
-------------
Here is a demo of the tool using the following scenario: We have pre-created 2 keypairs, namely ``test.pub / test.sec`` and ``test2.pub / test2.sec``, and we run the steps:

1. Encryption with a first public key, here `test.pub`
2. Decryption with the relevant private key (Here the `test.sec`, where the passphrase is given at a no-echo prompt, to unlock it)
3. Re-encryption with a second public key (Here `test2.pub` and the private key `test.sec` from 2)
4. Decryption using the second private key `test2.sec` (along with the no-echo prompted passphrase to unlock it).


.. image:: https://asciinema.org/a/ypkjaoDgQOGg2pILdFI4JlFGg.png
   :target: https://asciinema.org/a/ypkjaoDgQOGg2pILdFI4JlFGg
   :alt: Demo


Table of Contents
=================

.. toctree::
   :maxdepth: 2
   :name: toc

   Installation         <setup>
   Encryption           <encryption>
   Usage & Examples     <usage>
   Python Modules       <code>


|Travis| | Version |version| | Generated |today|


.. |Travis| image:: https://travis-ci.org/EGA-archive/crypt4gh.svg?branch=master
	:alt: Build Status
	:class: inline-baseline

.. |moreabout| unicode:: U+261E .. right pointing finger
.. |connect| unicode:: U+21cc .. <-_>
