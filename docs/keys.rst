.. note:: This utility supports OpenSSH key-format (version 6.5 or above)
	  if the key was generated with type ``ed25519`` (ie with ``ssh-keygen -t ed25519 ...``).
	  Otherwise, this utility can generate keys in the following format...


Crypt4GH Key Format
===================

A key is stored in the following PEM format:


::

    -----BEGIN CRYPT4GH <type> KEY-----
    BASE64-ENCODED DATA
    -----END CRYPT4GH <type> KEY-----

where ``<type>`` is either PUBLIC or PRIVATE

For a public key, the key data is the byte representation of the plaintext key material.

For a private key, we use the following encoding format.

::

   byte[]  MAGIC_WORD
   string  kdfname
   string  (rounds || salt)     # included if kdfname is not "none"
   string  ciphername
   string  private blob         # Key material encrypted or not
   string  comment              # Optional


The ``MAGIC_WORD`` is the byte-representation of the ASCII word "c4gh-v1".

Everything ``string`` consists of a length n (encoded as 2 big-endian bytes) and a sequence of n bytes.
For example, the string *hello*, is encoded as ``\x00\x05hello``.

The ``kdfname`` is the name of the Key Derivation Function. We support either ``scrypt``, ``pbkdf2_hmac_sha256``, ``bcrypt``, or ``none``. The python implementation uses scrypt when available, and defaults to bcrypt for generating keys.

``rounds`` is a 4 big-endian bytes representation of the number of iterations used in the KDF.

The ``ciphername`` describes which symmetric algorithm is used to generate the encrypted data, as follows.
The only supported cipher is ``chacha20_poly1305`` (so far), or ``none``.

When kdfname is none, so should the ciphername be (and vice-versa), and the ``(rounds || salt)`` string is not included. This is used when the key material is not encrypted.

In case the key material is encrypted, the KDF is used to derive a secret from a user-supplied passphrase.
A nonce is randomly generated, and used in conjunction with the secret to encrypt the private key, using Chacha20 and authenticated with Poly1305. The nonce is prepended to the encrypted data.

Finally, an optional comment can be used at the end of the encoded format.
