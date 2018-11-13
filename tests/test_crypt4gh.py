import os
import unittest
from testfixtures import tempdir, compare

import ed25519
from nacl.public import PrivateKey, PublicKey
from nacl.encoding import HexEncoder as KeyFormatter

from crypt4gh.crypt4gh import encrypt, decrypt, reencrypt, Header

from . import data as test_data

class TestCrypt4GH(unittest.TestCase):
    """Crypt4GH

    Testing Crypt4GH encryption/decryption and reencryption."""

    @tempdir()
    def test_encrypt(self, filedir):
        """Testing Crypt4GH encryption, encrypted file should have the necessary header."""
        infile = filedir.write('file.in', test_data.ORG_FILE)
        pubkey = PublicKey(test_data.PUBKEY_HEX, KeyFormatter)
        with open('file.in', 'rb') as inf, open('file.out', 'wb') as outf:
            encrypt(inf, outf, pubfile)
        compare(dir.read('file.out'), bytes.fromhex(test_data.ENC_FILE_HEX))
        filedir.cleanup()

    @tempdir()
    def test_encrypt_signed(self, filedir):
        """Testing Crypt4GH encryption, encrypted file should have the necessary header."""
        infile = filedir.write('file.in', test_data.ORG_FILE)
        pubkey = PublicKey(test_data.PUBKEY_HEX, KeyFormatter)
        signing_key = ed25519.SigningKey(bytes.fromhex(test_data.SIGNING_KEY_HEX))
        with open('file.in', 'rb') as inf, open('file.out', 'wb') as outf:
            encrypt(inf, outf, pubfile, signing_key=signing_key)
        compare(dir.read('file.out'), bytes.fromhex(test_data.ENC_FILE_HEX))
        filedir.cleanup()

    # @tempdir()
    # def test_decrypt(self, filedir):
    #     """Testing Crypt4GH decryption, should decrypt file properly."""
    #     infile = filedir.write('infile.in', bytearray.fromhex(test_data.ENC_FILE))
    #     keyfile = filedir.write('sec_key.asc', test_data.PGP_PRIVKEY.encode('utf-8'))
    #     outputdir = filedir.makedir('output')
    #     key, _ = pgpy.PGPKey.from_file(keyfile)
    #     outfile = open(os.path.join(outputdir, 'outputfile.out'), 'wb')

    #     def process_output(data):
    #         outfile.write(data)
    #     with key.unlock(test_data.PGP_PASSPHRASE) as privkey:
    #         decrypt(privkey, open(infile, 'rb'),  process_output=process_output)
    #         outfile.close()
    #     result = filedir.read(('output', 'outputfile.out'))
    #     self.assertEqual(test_data.ORG_FILE, result)
    #     filedir.cleanup()

    # @tempdir()
    # def test_reencryption(self, filedir):
    #     """Testing Crypt4GH reencryption, should have the proper header."""
    #     infile = filedir.write('infile.in', bytearray.fromhex(test_data.ENC_FILE))
    #     pub_keyfile = filedir.write('pub_key.asc', test_data.PGP_PUBKEY.encode('utf-8'))
    #     sec_keyfile = filedir.write('sec_key.asc', test_data.PGP_PRIVKEY.encode('utf-8'))
    #     outputdir = filedir.makedir('output')
    #     pub_key, _ = pgpy.PGPKey.from_file(pub_keyfile)
    #     sec_key, _ = pgpy.PGPKey.from_file(sec_keyfile)
    #     outfile = open(os.path.join(outputdir, 'outputfile.out'), 'wb')

    #     def process_output(data):
    #         outfile.write(data)
    #     with sec_key.unlock(test_data.PGP_PASSPHRASE) as privkey:
    #         reencrypt(pub_key, privkey, open(infile, 'rb'), process_output=process_output)
    #         outfile.close()
    #     result = filedir.read(('output', 'outputfile.out'))
    #     self.assertEqual(b'crypt4gh', result[:8])
    #     self.assertEqual(1, int.from_bytes(result[8:12], byteorder='little'))
    #     filedir.cleanup()

    # @tempdir()
    # def test_not_crypt4gh_header(self, filedir):
    #     """A file that has been encrypted in a different format, should trigger proper error."""
    #     infile = filedir.write('infile.in', bytearray.fromhex(test_data.BAD_ENC_FILE))
    #     with self.assertRaises(InvalidFormatError):
    #         get_header(open(infile, 'rb'))
    #     filedir.cleanup()

    # @tempdir()
    # def test_header(self, filedir):
    #     """Testing how the header content should formated and contain the SESSION_KEY."""
    #     infile = filedir.write('infile.in', bytearray.fromhex(test_data.ENC_FILE))
    #     sec_keyfile = filedir.write('sec_key.asc', test_data.PGP_PRIVKEY.encode('utf-8'))
    #     sec_key, _ = pgpy.PGPKey.from_file(sec_keyfile)
    #     with sec_key.unlock(test_data.PGP_PASSPHRASE) as privkey:
    #         header = Header.decrypt(get_header(open(infile, 'rb'))[1], privkey)
    #         self.assertEqual(test_data.RECORD_HEADER, str(header.records[0]))
    #         self.assertEqual(test_data.SESSION_KEY, header.records[0].session_key.hex())
    #         self.assertEqual(test_data.RECORD_HEADER_REPR, repr(header))
    #     filedir.cleanup()

    # @tempdir()
    # def test_header_bad_version(self, filedir):
    #     """Should raise ValueError for the wrong crypt4gh version."""
    #     infile = filedir.write('infile.in', bytearray.fromhex(test_data.BAD_HEADER_FILE))
    #     with self.assertRaises(VersionError):
    #         get_header(open(infile, 'rb'))

    # @tempdir()
    # def test_key_id(self, filedir):
    #     """Testing get_key_id, should return the KeyID."""
    #     infile = filedir.write('infile.in', bytearray.fromhex(test_data.ENC_FILE))
    #     _, header = get_header(open(infile, 'rb'))
    #     self.assertEqual(test_data.KEY_ID, get_key_id(header))
    #     filedir.cleanup()

    # @tempdir()
    # def test_header_to_records(self, filedir):
    #     """Should return one header record."""
    #     infile = filedir.write('infile.in', bytearray.fromhex(test_data.ENC_FILE))
    #     _, header = get_header(open(infile, 'rb'))
    #     result = header_to_records(test_data.PGP_PRIVKEY, header, test_data.PGP_PASSPHRASE)
    #     self.assertEqual(1, len(result))
    #     self.assertEqual(test_data.RECORD_HEADER, str(result[0]))
    #     filedir.cleanup()

    # def test_do_nothing(self):
    #     """It sould do nothing."""
    #     do_nothing("data")
