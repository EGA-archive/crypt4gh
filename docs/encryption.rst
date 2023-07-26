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


AEAD mode
---------

The procedure to use the AEAD mode is as follows: |br| We randomly
pick a number, and create an incrementing sequence starting at that
number (We limit the number to 8 bytes, so the sequence can eventually
wrap around). |br| For each encrypted segment, in order, we attach the
number we pop from the sequence. |br| In case the end of the file
lands on a segment boundary, we also encrypt an empty segment, using
the incrementing sequence, and add it as last encrypted segment.

The AEAD mode ensures no segments can be lost or re-ordered.

It is the default mode and the non-AEAD mode is kept for backwards compatibility using the ``-n`` switch (See :ref:`Usage & Examples <cli-usage>`).

In the AEAD mode, the header contains a data encryption packet with method ``1``, and the data encryption parameters are the session key followed by the initial sequence number from the above sequence.

.. note:: Data Encryption methods can't be mixed.

.. |br| raw:: html

   <br />
