[![Documentation Status](https://readthedocs.org/projects/crypt4gh/badge/?version=latest)](https://crypt4gh.readthedocs.io/en/latest/?badge=latest)
[![Testsuite](https://github.com/EGA-archive/crypt4gh/workflows/Testsuite/badge.svg)](https://github.com/EGA-archive/crypt4gh/actions)

# Crypt4GH Encryption Utility

`crypt4gh`is a Python tool to encrypt, decrypt or re-encrypt files, according to the [GA4GH encryption file format](https://www.ga4gh.org/news/crypt4gh-a-secure-method-for-sharing-human-genetic-data/).


## Installation

Python `3.6+` required to use the crypt4gh encryption utility.

Install it from PyPI:

```
pip install crypt4gh
```

or if you prefer the latest sources from Github:

```
git clone https://github.com/EGA-archive/crypt4gh
pip install -r crypt4gh/requirements.txt
pip install ./crypt4gh
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
   {PROG} [-hv] [--log <file>] encrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--range <start-end>]
   {PROG} [-hv] [--log <file>] decrypt [--sk <path>] [--sender_pk <path>] [--range <start-end>]
   {PROG} [-hv] [--log <file>] rearrange [--sk <path>] --range <start-end>
   {PROG} [-hv] [--log <file>] reencrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--trim]

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <file>           Path to the logger file (in YML format)
   --sk <keyfile>         Curve25519-based Private key.
                          When encrypting, if neither the private key nor C4GH_SECRET_KEY are specified, we generate a new key 
   --recipient_pk <path>  Recipient's Curve25519-based Public key
   --sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (akin to signature)
   --range <start-end>    Byte-range either as  <start-end> or just <start> (Start included, End excluded)
   -t, --trim             Keep only header packets that you can decrypt


Environment variables:
   C4GH_LOG         If defined, it will be used as the default logger
   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${C4GH_SECRET_KEY})
 
```

## Demonstration

Alice and Bob generate both a pair of public/private keys.

```bash
$ crypt4gh-keygen --sk alice.sec --pk alice.pub
$ crypt4gh-keygen --sk bob.sec --pk bob.pub
```

Bob encrypts a file for Alice:

```bash
$ crypt4gh encrypt --sk bob.sec --recipient_pk alice.pub < file > file.c4gh
```

Alice decrypts the encrypted file:

```bash
$ crypt4gh decrypt --sk alice.sec < file.c4gh
```

[![asciicast](https://asciinema.org/a/mmCBfBdCFfcYCRBuTSe3kjCFs.svg)](https://asciinema.org/a/mmCBfBdCFfcYCRBuTSe3kjCFs)

## File Format

Refer to the [specifications](http://samtools.github.io/hts-specs/crypt4gh.pdf) or this [documentation](https://crypt4gh.readthedocs.io/en/latest/encryption.html).
