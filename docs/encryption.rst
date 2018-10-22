Encryption Algorithm - Crypt4GH
===============================

A random session key (of 256 bits) is generated to seed an ChaCha20
engine, with Poly1305 authentication mode. A nonce is also randomly
generated for the engine, along with a counter. Using the two latters,
the original file is encrypted and a header is prepended to the
encrypted data. The file is chunked in blocks of 64 kB.

Informally, the header contains, in order, the word ``crypt4gh``, the
format version (currently 1), the length of the remainder of the
header and the remainder.

The remainder of the header is encrypted using elliptic curve 25519.

.. image:: /static/encryption.png
   :target: ../_static/encryption.png
   :alt: Encryption

The advantages of the format are, among others:

* Re-encrypting the file for another user requires only to decrypt the header and encrypt it with the user's public key.
* Ingesting the file does not require a decryption step. `(Note: That is done in the verification step)`.
* The counter offset allows to encrypt/decrypt only part of the file, and/or run the cryptographic tasks in parallel.
