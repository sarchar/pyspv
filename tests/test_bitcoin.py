import unittest

from pyspv import Bitcoin, hexstring_to_bytes

class BitcoinSHA256(unittest.TestCase):
    vectors = [
        (b'abc', hexstring_to_bytes('4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358', False)),
        (b'crazy horse battery staple', hexstring_to_bytes('83e8d1654ddd49726cebed16b32cbfd7ac807f66d2fcad8dc61c774e38812ae2', False)),
    ]

    def testsha256(self):
        for src, result in BitcoinSHA256.vectors:
            self.assertEqual(Bitcoin.hash(src), result)

