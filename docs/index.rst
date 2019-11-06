======================
Crypt4GH utility
======================

Bob wants to send a message to Alice, containing sensitive data. Bob
uses `Crypt4GH, the Global Alliance approved secure method for sharing human genetic data <https://www.ga4gh.org/news/crypt4gh-a-secure-method-for-sharing-human-genetic-data/>`_.

`crypt4gh`, a Python tool to encrypt, decrypt or re-encrypt files,
according to the :download:`GA4GH encryption file format
<http://samtools.github.io/hts-specs/crypt4gh.pdf>`.

.. image:: https://www.ga4gh.org/wp-content/uploads/Crypt4GH_comic.png
   :target: https://www.ga4gh.org/news/crypt4gh-a-secure-method-for-sharing-human-genetic-data/
   :alt: How Crypt4GH works

----

Alice and Bob generate both a pair of public/private keys.

.. code-block:: console

   crypt4gh-keygen --sk alice.sec --pk alice.pub
   crypt4gh-keygen --sk bob.sec --pk bob.pub


Bob encrypts a file for Alice:

.. code-block:: console

   $ crypt4gh encrypt --sk bob.sec --recipient_pk alice.pub < file > file.c4gh

Alice decrypts the encrypted file:

.. code-block:: console

   $ crypt4gh decrypt --sk alice.sec < file.c4gh


.. image:: https://asciinema.org/a/mmCBfBdCFfcYCRBuTSe3kjCFs.png
   :target: https://asciinema.org/a/mmCBfBdCFfcYCRBuTSe3kjCFs
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

