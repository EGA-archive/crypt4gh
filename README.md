
`crypt4gh` is a tool to encrypt, decrypt or re-encrypt files
according to the [GA4GH cryptographic standard](https://github.com/daviesrob/hts-specs/tree/crypt4gh_improved).

# Installation

```
git clone https://github.com/EGA-archive/crypt4gh
pip install -r crypt4gh/requirements.txt
pip install -e ./crypt4gh
```

or

```
pip install git+https://github.com/EGA-archive/crypt4gh.git
```

# Usage

The usual `-h` flag shows you the different options that the tool accepts.

```bash
$ crypt4gh -h
Utility for the cryptographic GA4GH standard.
Reads from stdin and Outputs to stdout

Usage:
   crypt4gh [-hv] [--log <file>] encrypt [--signing_key <file>] [--pk <path>]
   crypt4gh [-hv] [--log <file>] decrypt [--sk <path>]
   crypt4gh [-hv] [--log <file>] reencrypt [--signing_key <file>] [--sk <path>] [--pk <path>]
   crypt4gh [-hv] [--log <file>] generate [-f <path>] [-P <passphrase>] [--signing]

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <file>           Path to the logger file (in YML format)
   --pk <keyfile>         Public Curve25519 key to be used for encryption
   --sk <keyfile>         Private Curve25519 key to be used for decryption
   --signing_key <file>   Ed25519 Signing key for the header
   -f <path>              Private Curve25519 key (.pub is appended for the Public one) [default: ~/.lega/ega.key]
   -P <passphrase>        Passphrase to lock the secret key [default: None]
   --signing              Generate an ed25519 signing/verifying keypair

Environment variables:
   LEGA_LOG         If defined, it will be used as the default logger
   LEGA_PUBLIC_KEY  If defined, it will be used as the default public key (ie --pk ${LEGA_PUBLIC_KEY})
   LEGA_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${LEGA_SECRET_KEY})
   LEGA_SIGNING_KEY If defined, it will be used as the default signing key (ie --signing_key ${LEGA_SIGNING_KEY})```
```

# Examples

If you want to encrypt a file, say, for the Swedish Local EGA instance:

```bash
$ crypt4gh encrypt --pk path_to_pubkey < inputfile > outputfile
```
# File Format

Refer to the [following slide](https://docs.google.com/presentation/d/1Jg0cUCLBO7ctyIWiyTmxb5Il_fQVzKzrxHHzR0K9ZvU/edit#slide=id.g3b7e5ab607_0_2?usp=sharing)

# Demonstration

Here is a demo of the tool using the following scenario: We have pre-created 2 keypairs, namely `test.pub / test.sec` and `test2.pub / test2.sec`, and we run the steps:

1. Encryption with a first public key, here `test.pub`
2. Decryption with the relevant private key (Here the `test.sec`, where the passphrase is given at a no-echo prompt, to unlock it)
3. Re-encryption with a second public key (Here `test2.pub` and the private key `test.sec` from 2)
4. Decryption using the second private key `test2.sec` (along with the no-echo prompted passphrase to unlock it).

[![asciicast](https://asciinema.org/a/ypkjaoDgQOGg2pILdFI4JlFGg.png)](https://asciinema.org/a/ypkjaoDgQOGg2pILdFI4JlFGg)
