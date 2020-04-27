# Crypt4GH testsuite

We run the following tests using [BATS](https://github.com/bats-core/bats-core).

These tests treat the system as a black box, only checking the expected output for a given input.

We use 2 users: Alice and Bob.

## Full file Encryption/Decryption

We use a `testfile` containing the sequence of letters `abcd`, where each letter is repeated 65536 times.

- [x] Bob encrypts a 10MB file for Alice, and Alice decrypts it<br/>
      Expected outcome: Alice reads the same content as Bob had.

- [x] Bob encrypts the testfile for Alice, and Alice decrypts it<br/>
      Expected outcome: Alice reads the same content as testfile.

- [x] Bob encrypts the testfile for himself<br/>
      Bob takes the resulting file and only changes the recipient to be Alice.
      Alice decrypts what she receives
      Expected outcome: Alice reads the same content as testfile.

## Segmenting an encrypted file

We use the testfile and Bob encrypts it for himself.

- [x] Bob encrypts only the "b"'s from the testfile for Alice, using the `--range` flag<br/>
      Alice decrypts what she receives
      Expected outcome: Alice reads 65536 "b"s.

- [x] Bob rerranges the encrypted file using the `--range 65536-131073` flag, to only the "b"s<br/>
      Bob takes the resulting file and only changes the recipient to be Alice.
      Alice decrypts what she receives
      Expected outcome: Alice reads 65536 "b"s.
  
- [x] Bob rerranges the encrypted file using the `--range 65535-131074` flag, for Alice, to match one "a", all the "b"s, and one "c"<br/>
      Expected outcome: Alice reads one "a", 65536 "b"s and one "c".

- [x] Bob sends the secret message `Let's have beers in the sauna! or Dinner at 7pm?` to Alice.
      The message is buried in the middle of some random data.
      Alice decrypts what she receives
      Expected outcome: Alice reads `Let's have beers in the sauna! or Dinner at 7pm?`.


## Using SSH keys


- [x] Bob encrypts a 10MB file for Alice, using his own SSH keypair, and Alice decrypts it, using her Crypt4GH keypair<br/>
      Expected outcome: Alice reads the same content as Bob had.

- [x] Bob encrypts a 10MB file for Alice, using his own Crypt4GH keypair, and Alice decrypts it, using her SSH keypair<br/>
      Expected outcome: Alice reads the same content as testfile.

- [x] Bob encrypts a 10MB file for Alice, and Alice decrypts it, both using their SSH keypair<br/>
      Expected outcome: Alice reads the same content as testfile.


## Multiple recipients


- [x] Bob sends the testfile secretly to himself and Alice<br/>
      Expected outcome: They both can read the same content as Bob had.

- [x] Bob encrypts the testfile for himself and reencrypts it for himself and Alice<br/>
      Expected outcome: They both can read the same content as Bob had.



