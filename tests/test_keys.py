import unittest

from pyspv import Bitcoin, keys, hexstring_to_bytes

class AddressTestBitcoinKeys(unittest.TestCase):
    test_vectors = [
        (hexstring_to_bytes('0000000000000000000000000000000000000000000000000000000000000001', reverse=False), 
            '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf',
            False, '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm'),
        (hexstring_to_bytes('0000000000000000000000000000000000000000000000000000000000000001', reverse=False), 
            'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
            True, '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'),
        # TODO : more...
    ]

    def test_private_keys(self):
        for pk_bytes, wif, is_compressed, bitcoin_address in AddressTestBitcoinKeys.test_vectors:
            private_key = keys.PrivateKey(pk_bytes)
            self.assertEqual(private_key.as_wif(Bitcoin, is_compressed), wif)
            public_key = private_key.get_public_key(is_compressed)
            self.assertEqual(public_key.as_address(Bitcoin), bitcoin_address)

class AddressTestSerialization(unittest.TestCase):

    def test_serialize_private_key(self):
        pk = keys.PrivateKey(Bitcoin.hash(b'test case'))
        data = pk.serialize()
        pk2, v = keys.PrivateKey.unserialize(data)
        self.assertEqual(v, b'')
        self.assertEqual(pk, pk2)

    def test_serialize_public_key(self):
        pubkey = keys.PrivateKey(Bitcoin.hash(b'test case')).get_public_key(False)
        data = pubkey.as_hex()
        pubkey2 = keys.PublicKey.from_hex(data)
        self.assertEqual(pubkey, pubkey2)
        
        
