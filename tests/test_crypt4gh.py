import os
import unittest
from testfixtures import tempdir

import pgpy

from legacryptor.exceptions import InvalidFormatError, VersionError, MDCError
from legacryptor.crypt4gh import encrypt, decrypt, reencrypt, get_header, Header, get_key_id, do_nothing, header_to_records
from . import pgp_data


class TestCrypt4GH(unittest.TestCase):
    """Crypt4GH

    Testing Crypt4GH encryption/decryption and reencryption."""

    @tempdir()
    def test_encrypt(self, filedir):
        """Testing Crypt4GH encryption, encrypted file should have the necessary header."""
        infile = filedir.write('infile.in', pgp_data.ORG_FILE)
        keyfile = filedir.write('pub_key.asc', pgp_data.PGP_PUBKEY.encode('utf-8'))
        outputdir = filedir.makedir('output')
        key, _ = pgpy.PGPKey.from_file(keyfile)
        encrypt(key, open(infile, 'rb'), None, open(os.path.join(outputdir, 'outputfile.out'), 'wb'))
        result = filedir.read(('output', 'outputfile.out'))
        # 6372797074346768 in string format is crypt4gh
        self.assertTrue(str.startswith(result.hex(), '6372797074346768'))
        # checking that the first 8 bytes are crypt4gh
        self.assertEqual(b'crypt4gh', result[:8])
        self.assertEqual(1, int.from_bytes(result[8:12], byteorder='little'))
        filedir.cleanup()

    @tempdir()
    def test_decrypt(self, filedir):
        """Testing Crypt4GH decryption, should decrypt file properly."""
        infile = filedir.write('infile.in', bytearray.fromhex(pgp_data.ENC_FILE))
        keyfile = filedir.write('sec_key.asc', pgp_data.PGP_PRIVKEY.encode('utf-8'))
        outputdir = filedir.makedir('output')
        key, _ = pgpy.PGPKey.from_file(keyfile)
        outfile = open(os.path.join(outputdir, 'outputfile.out'), 'wb')

        def process_output(data):
            outfile.write(data)
        with key.unlock(pgp_data.PGP_PASSPHRASE) as privkey:
            decrypt(privkey, open(infile, 'rb'),  process_output=process_output)
            outfile.close()
        result = filedir.read(('output', 'outputfile.out'))
        self.assertEqual(pgp_data.ORG_FILE, result)
        filedir.cleanup()

    @tempdir()
    def test_reencryption(self, filedir):
        """Testing Crypt4GH reencryption, should have the proper header."""
        infile = filedir.write('infile.in', bytearray.fromhex(pgp_data.ENC_FILE))
        pub_keyfile = filedir.write('pub_key.asc', pgp_data.PGP_PUBKEY.encode('utf-8'))
        sec_keyfile = filedir.write('sec_key.asc', pgp_data.PGP_PRIVKEY.encode('utf-8'))
        outputdir = filedir.makedir('output')
        pub_key, _ = pgpy.PGPKey.from_file(pub_keyfile)
        sec_key, _ = pgpy.PGPKey.from_file(sec_keyfile)
        outfile = open(os.path.join(outputdir, 'outputfile.out'), 'wb')

        def process_output(data):
            outfile.write(data)
        with sec_key.unlock(pgp_data.PGP_PASSPHRASE) as privkey:
            reencrypt(pub_key, privkey, open(infile, 'rb'), process_output=process_output)
            outfile.close()
        result = filedir.read(('output', 'outputfile.out'))
        self.assertEqual(b'crypt4gh', result[:8])
        self.assertEqual(1, int.from_bytes(result[8:12], byteorder='little'))
        filedir.cleanup()

    @tempdir()
    def test_not_crypt4gh_header(self, filedir):
        """A file that has been encrypted in a different format, should trigger proper error."""
        infile = filedir.write('infile.in', bytearray.fromhex(pgp_data.BAD_ENC_FILE))
        with self.assertRaises(InvalidFormatError):
            get_header(open(infile, 'rb'))
        filedir.cleanup()

    @tempdir()
    def test_header(self, filedir):
        """Testing how the header content should formated and contain the SESSION_KEY."""
        infile = filedir.write('infile.in', bytearray.fromhex(pgp_data.ENC_FILE))
        sec_keyfile = filedir.write('sec_key.asc', pgp_data.PGP_PRIVKEY.encode('utf-8'))
        sec_key, _ = pgpy.PGPKey.from_file(sec_keyfile)
        with sec_key.unlock(pgp_data.PGP_PASSPHRASE) as privkey:
            header = Header.decrypt(get_header(open(infile, 'rb'))[1], privkey)
            self.assertEqual(pgp_data.RECORD_HEADER, str(header.records[0]))
            self.assertEqual(pgp_data.SESSION_KEY, header.records[0].session_key.hex())
            self.assertEqual(pgp_data.RECORD_HEADER_REPR, repr(header))
        filedir.cleanup()

    @tempdir()
    def test_header_bad_version(self, filedir):
        """Should raise ValueError for the wrong crypt4gh version."""
        infile = filedir.write('infile.in', bytearray.fromhex(pgp_data.BAD_HEADER_FILE))
        with self.assertRaises(VersionError):
            get_header(open(infile, 'rb'))

    @tempdir()
    def test_key_id(self, filedir):
        """Testing get_key_id, should return the KeyID."""
        infile = filedir.write('infile.in', bytearray.fromhex(pgp_data.ENC_FILE))
        _, header = get_header(open(infile, 'rb'))
        self.assertEqual(pgp_data.KEY_ID, get_key_id(header))
        filedir.cleanup()

    @tempdir()
    def test_header_to_records(self, filedir):
        """Should return one header record."""
        infile = filedir.write('infile.in', bytearray.fromhex(pgp_data.ENC_FILE))
        _, header = get_header(open(infile, 'rb'))
        result = header_to_records(pgp_data.PGP_PRIVKEY, header, pgp_data.PGP_PASSPHRASE)
        self.assertEqual(1, len(result))
        self.assertEqual(pgp_data.RECORD_HEADER, str(result[0]))
        filedir.cleanup()

    def test_do_nothing(self):
        """It sould do nothing."""
        do_nothing("data")
