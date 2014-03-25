import hashlib
import unittest

from pyspv import hexstring_to_bytes, bytes_to_hexstring

class TestBytes(unittest.TestCase):
    def test1(self):
        hasher = hashlib.sha256()
        hasher.update(b'test case')
        data = hasher.digest()
        self.assertEqual(bytes_to_hexstring(data, reverse=False), '{:064x}'.format(int.from_bytes(data, 'big')))
        self.assertEqual(hexstring_to_bytes(bytes_to_hexstring(data, reverse=False), reverse=False), data)

    def test2(self):
        hasher = hashlib.sha256()
        hasher.update(b'test case 2')
        data = hasher.digest()
        self.assertEqual(bytes_to_hexstring(data, reverse=True), '{:064x}'.format(int.from_bytes(data, 'little')))
        self.assertEqual(hexstring_to_bytes(bytes_to_hexstring(data, reverse=True), reverse=True), data)

