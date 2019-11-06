Encryption Algorithm - Crypt4GH
===============================

A random session key (of 256 bits) is generated to seed a ChaCha20
engine, with Poly1305 authentication mode. For each segment of at most
64kB of data, a nonce is randomly generated and prepended to the
segment. Using the two latters, the original file is segmented and
each segment is encrypted.

The header is prepended to the encrypted data.

Informally, the header contains, the word ``crypt4gh``, the
format version (currently 1), the number of header packets, and the sequence of header packets.

A header packet is a length followed by its content. The content can be a data encryption packet or an edit list packet.

All packets are encrypted using a Curve25519-based encryption.

.. image:: /static/encryption.png
   :target: ../_static/encryption.png
   :alt: Encryption

The advantages of the format are, among others:

* Re-encrypting the file for another user requires only to decrypt the header and encrypt it with the user's public key.
* Header packets can be encrypted for multiple recipients.
* Re-arranging the file to chunk a portion requires only to decrypt the header, re-encrypt with an edit list, and select the cipher segments surrounding the portion. The file itself is not decrypted and reencrypted.
