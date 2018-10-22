import unittest
from legacryptor.pubring import Pubring
from testfixtures import TempDirectory, tempdir
from . import pgp_data
from terminaltables import DoubleTable
from unittest import mock


class TestPubring(unittest.TestCase):
    """Pubring

    Testing Pubring."""

    def setUp(self):
        """Setting things up."""
        self._dir = TempDirectory()
        self._path = self._dir.write('pubring.bin', pgp_data.PGP_PUBKEY.encode('utf-8'))
        self._pubring = Pubring(self._path)

    def tearDown(self):
        """Remove files."""
        self._dir.cleanup_all()

    @tempdir()
    def test_unproper_keyring(self, filedir):
        """Setting up should give an error due to unproper armored PGP."""
        path = filedir.write('pubring.bin', ''.encode('utf-8'))
        # the ValueError is raised by PGPy because unproper armored PGP
        with self.assertRaises(ValueError):
            Pubring(path)
        filedir.cleanup()

    @tempdir()
    @mock.patch('legacryptor.pubring.LegaKeyring')
    def test_empty_keyring(self, mock_keyring, filedir):
        """The keyring is empty, thus it should point that out."""
        mock_keyring.return_value = ''
        path = filedir.write('pubring.bin', ''.encode('utf-8'))
        with self.assertRaises(ValueError):
            Pubring(path)
        filedir.cleanup()

    def test_load_key(self):
        """Pubring getitem, should return the key."""
        # This identified a bug for example if there is no version in the PGP_PUBKEY
        # PGPy adds its own version e.g. Version: PGPy v0.4.3

        # for some reason PGPy adds a new line at the end
        data_name = str(self._pubring.__getitem__(pgp_data.PGP_NAME)).rstrip()  # get by name
        self.assertEqual(pgp_data.PGP_PUBKEY, data_name)
        data_key_id = str(self._pubring.__getitem__(pgp_data.KEY_ID)).rstrip()  # get by key_id
        self.assertEqual(pgp_data.PGP_PUBKEY, data_key_id)
        data_comment = str(self._pubring.__getitem__(pgp_data.PGP_COMMENT)).rstrip()  # get by key_id
        self.assertEqual(pgp_data.PGP_PUBKEY, data_comment)
        data_email = str(self._pubring.__getitem__(pgp_data.PGP_EMAIL)).rstrip()  # get by key_id
        self.assertEqual(pgp_data.PGP_PUBKEY, data_email)

    def test_pubring_notempty(self):
        """Pubring should not be empty, and this should be True."""
        self.assertTrue(bool(self._pubring))

    def test_pubring_str(self):
        """Should return the pubring path."""
        self.assertEqual(f'<Pubring from {self._path}>', str(self._pubring))

    def test_pubring_iter(self):
        """Get pubring items, should return the expected list."""
        list = [x for x in iter(self._pubring)]
        expected = [(pgp_data.KEY_ID, pgp_data.PGP_NAME, pgp_data.PGP_EMAIL, pgp_data.PGP_COMMENT)]
        self.assertEqual(expected, list)

    def test_pubring_repr(self):
        """Get the table info from Pubring."""
        list_data = [('Key ID', 'User Name', 'User Email', 'User Comment')]
        list_data.append((pgp_data.KEY_ID, pgp_data.PGP_NAME, pgp_data.PGP_EMAIL, pgp_data.PGP_COMMENT))
        table = DoubleTable(list_data)
        data = f'''\
Available keys from {self._path}
{table.table}
The first substring that matches the requested recipient will be used as the encryption key
Alternatively, you can use the KeyID itself'''
        self.assertEqual(data, repr(self._pubring))
