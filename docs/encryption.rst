Encryption Algorithm - Crypt4GH
===============================

A random session key (of 256 bits) is generated to seed an ChaCha20
engine, with Poly1305 authentication mode. For each segment of at most
64kB of data, a nonce is randomly generated and prepended to the
segment. Using the two latters, the original file is segmented and
each segment is encrypted. The last segment may contain a checksum of
the original file, if stated in the header.

The header is prepended to the encrypted data.

Informally, the header contains, the word ``crypt4gh``, the
format version (currently 1), the length of the remainder of the
header and the remainder.

The remainder of the header contains encrypted data, using a Curve25519-based encryption.

.. image:: /static/encryption.png
   :target: ../_static/encryption.png
   :alt: Encryption

The advantages of the format are, among others:

* Re-encrypting the file for another user requires only to decrypt the header and encrypt it with the user's public key.
* Ingesting the file does not require a decryption step. `(Note: That is done in the verification step)`.
* The counter offset allows to encrypt/decrypt only part of the file, and/or run the cryptographic tasks in parallel.
