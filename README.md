# Crypt4GH Encryption Utility

`crypt4gh` is a tool to encrypt, decrypt or re-encrypt files
according to the [Crypt4GH Encryption format](specs).

## Installation

Python `3.6+` required to use the crypt4gh encryption utility.

```
git clone https://github.com/EGA-archive/crypt4gh
pip install -r crypt4gh/requirements.txt
pip install -e ./crypt4gh
```

or

```
pip install git+https://github.com/EGA-archive/crypt4gh.git
```

## Usage

The usual `-h` flag shows you the different options that the tool accepts.

```bash
$ crypt4gh -h
Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.

Usage:
   crypt4gh [-hv] [--log <file>] encrypt [--sk <path>] --recipient_pk <path>
   crypt4gh [-hv] [--log <file>] decrypt [--sk <path>] [--sender_pk <path>] [--range <start-end>]
   crypt4gh [-hv] [--log <file>] reencrypt [--sk <path>] --recipient_pk <path> [--sender_public_key <path>]
   crypt4gh [-hv] [--log <file>] generate [-f] [--pk <path>] [--sk <path>] [--nocrypt] [-C <comment>] [-R <rounds>]

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <file>           Path to the logger file (in YML format)
   --sk <keyfile>         Curve25519-based Private key [default: ~/.c4gh/key]
   --pk <keyfile>         Curve25519-based Public key  [default: ~/.c4gh/key.pub]
   --recipient_pk <path>  Recipient's Curve25519-based Public key
   --sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (aka, signature)
   -C <comment>           Key's Comment
   --nocrypt              Do not encrypt the private key.
                          Otherwise it is encrypted in the Crypt4GH key format
   -R <rounds>            Numbers of rounds for the key derivation. Ignore it to use the defaults.
   -f                     Overwrite the destination files
   --range <start-end>    Byte-range either as  <start-end> or just <start>.

Environment variables:
   C4GH_LOG         If defined, it will be used as the default logger
   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${C4GH_SECRET_KEY})
```

## Demonstration

Alice and Bob generate both a pair of public/private keys.

```bash
$ crypt4gh generate --sk alice.sec --pk alice.pub
$ crypt4gh generate --sk bob.sec --pk bob.pub
```

Bob encrypts a file for Alice:

```bash
$ crypt4gh encrypt --sk bob.sec --recipient_pk alice.pub < file > file.c4gh
```

Alice decrypts the encrypted file:

```bash
$ crypt4gh decrypt --sk alice.sec < file.c4gh
```

[![asciicast](https://asciinema.org/a/JtctM4ATUBpGM3oQqbQ2Sr6B4.svg)](https://asciinema.org/a/JtctM4ATUBpGM3oQqbQ2Sr6B4)

## File Format

Refer to the [specifications](docs/static/crypt4gh.pdf) or this [documentation](https://crypt4gh.readthedocs.io/en/latest/encryption.html).
