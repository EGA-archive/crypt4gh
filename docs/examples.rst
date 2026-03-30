Examples
========

Assume Alice, with public/private key alice.pub and alice.sec respectively, wants to send a message to Bob, with public/private key bob.pub and bob.sec respectively.

Alice can encrypt the message M with:

.. code-block:: console

    $ crypt4gh encrypt --sk alice.sec --recipient_pk bob.pub < M > M.c4gh

Bob can decrypt the encrypted message with:

.. code-block:: console

    $ crypt4gh decrypt --sk bob.sec < M.c4gh > M

If Bob wants to, optionally, verify that the message indeed comes from Alice, he needs to fetch Alice's public key via another trusted channel. He can then decrypt *and* check the provenance of the file with:

.. code-block:: console

    $ crypt4gh decrypt --sk bob.sec --sender_pk alice.pub < M.c4gh > M

Any user can generate a keypair with:

.. code-block:: console

    $ crypt4gh-keygen --sk user.sec --pk user.pub

The private key will be encrypted with a passphrase. The user is prompted at the terminal for that passphrase.

Storing the encrypted header separately
---------------------------------------

The encrypted header can be stored separately from the encrypted payload. Splitting header from payload is useful when payloads are stored in a shared location, for example. In this case, only the header needs to be re-encrypted (for a specific recipient) while the encrypted payload remains untouched.

To store the encrypted header in a separate file ``header.bob.c4gh``, use the flag ``--header``. Alice sends a message to Bob (and herself), sharing the message payload.

.. code-block:: console

    $ crypt4gh encrypt --sk alice.sec --recipient_pk bob.pub --recipient_pk alice.pub --header header.bob.c4gh < M > M.payload.c4gh

Bob can then decrypt the message by concatenating the header and the payload, and decrypting the whole file:

.. code-block:: console

    $ cat header.bob.c4gh M.payload.c4gh | crypt4gh decrypt --sk bob.sec > M

To re-encrypt the message for another user Eve, with public key ``eve.pub``, Alice can run the ``crypt4gh reencrypt`` command: 

.. code-block:: console

    $ crypt4gh reencrypt --sk alice.sec --recipient_pk eve.pub < header.bob.c4gh > header.eve.c4gh
    # Alice can decrypt header.bob.c4gh, she is a recipient

Eve can now also read the same payload with:

.. code-block:: console

    $ cat header.eve.c4gh M.payload.c4gh | crypt4gh decrypt --sk eve.sec > M
