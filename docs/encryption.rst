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

The procedure to use the AEAD mode is as follows: |br| Each session
key is paired with a randomly picked number, called the *sequnce
number*. |br| For each encrypted segment, in order, at index ``i``
(starting at 0), we attach the authenticated data composed of sequence
number incremented by ``i``. The latter number is limited to 8 bytes,
so it can eventually wrap around. |br| In case the end of the file
lands on a segment boundary, we also encrypt an empty segment (at the
last index), and append it as last encrypted segment.

The AEAD mode ensures no segments can be lost or re-ordered.

It is the default mode in the `python implementation <https://pypi.org/project/crypt4gh/>`_ and the non-AEAD mode is kept for backwards compatibility using the ``-n`` switch (See :ref:`Usage & Examples <cli-usage>`).

In the AEAD mode, the header contains a data encryption packet with method ``1``, and the data encryption parameters are the session key paired with a sequence number. If several such packets are present, the encryption method can not be mixed.

.. note:: Data Encryption methods can't be mixed.

.. |br| raw:: html

   <br />
