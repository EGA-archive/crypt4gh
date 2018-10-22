Encryption Algorithm - Crypt4GH
===============================

A random session key (of 256 bits) is generated to seed an AES engine,
in CTR mode. An initialization vector (IV) is also randomly generated
for the engine. Using the two latters, the original file is encrypted
and a header is prepended to the encrypted data.

Informally, the header contains, in order, the word ``crypt4gh``, the
format version (currently 1), the length of the remainder of the
header and the remainder.

The remainder is an `OpenPGP <https://tools.ietf.org/html/rfc4880>`_
encrypted message that contains *records*.  A record encapsulates a
section of the original file, the randomly-generated session key and
IV, and the counter offset.

.. image:: /static/encryption.png
   :target: ../_static/encryption.png
   :alt: Encryption


The advantages of the format are, among others:

* Re-encrypting the file for another user requires only to decrypt the header and encrypt it with the user's public key.
* Ingesting the file does not require a decryption step. `(Note: That is done in the verification step)`.
* Possibility to encrypt parts of the file using different session keys
* The CTR offset allows to encrypt/decrypt only part of the file, and/or run the cryptographic tasks in parallel.
