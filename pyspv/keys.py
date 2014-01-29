import ctypes

from .serialize import Serialize, SerializeDataTooShort
from .util import *

try:
    ssl_library = ctypes.cdll.LoadLibrary('libeay32.dll')
except:
    ssl_library = ctypes.cdll.LoadLibrary('libssl.so')

NID_secp160k1 = 708
NID_secp256k1 = 714

class PublicKey:
    def __init__(self, pubkey):
        self.pubkey = pubkey

    def is_compressed(self):
        return self.pubkey[0] in (0x02, 0x03) and len(self.pubkey) == 33

    def as_hex(self, coin):
        return bytes_to_hexstring(self.pubkey, reverse=False)

    def as_address(self, coin):
        return base58_check(coin, coin.hash160(self.pubkey), version_bytes=coin.ADDRESS_VERSION_BYTES)

    @staticmethod
    def compress(pubkey):
        assert pubkey[0] == 0x04
        x_coord = pubkey[1:33]
        if pubkey[64] & 0x01:
            c = bytes([0x03]) + x_coord
        else:
            c = bytes([0x02]) + x_coord
        return c

    @staticmethod
    def from_hex(self, s):
        pubkey = hexstring_to_bytes(s, reverse=False)
        return PublicKey(pubkey)

class PrivateKey:
    def __init__(self, secret):
        self.secret = secret

    def __hash__(self):
        return int.from_bytes(self.secret, 'little')

    def __eq__(self, other):
        return self is other or (self.__class__ is other.__class__ and self.secret == other.secret)

    def as_wif(self, coin, compressed):
        '''WIF - wallet import format'''
        return base58_check(coin, self.secret + (b'\x01' if compressed else b''), version_bytes=coin.PRIVATE_KEY_VERSION_BYTES)

    def get_public_key(self, compressed):
        k = ssl_library.EC_KEY_new_by_curve_name(NID_secp256k1)
        
        storage = ctypes.create_string_buffer(self.secret)
        bignum_private_key = ssl_library.BN_new()
        ssl_library.BN_bin2bn(storage, 32, bignum_private_key)

        group = ssl_library.EC_KEY_get0_group(k)
        point = ssl_library.EC_POINT_new(group)

        ssl_library.EC_POINT_mul(group, point, bignum_private_key, None, None, None)
        ssl_library.EC_KEY_set_private_key(k, bignum_private_key)
        ssl_library.EC_KEY_set_public_key(k, point)

        size = ssl_library.i2o_ECPublicKey(k, 0)
        storage = ctypes.create_string_buffer(size)
        pstorage = ctypes.pointer(storage)
        ssl_library.i2o_ECPublicKey(k, ctypes.byref(pstorage))
        public_key = storage.raw

        ssl_library.EC_POINT_free(point)
        ssl_library.BN_free(bignum_private_key)
        ssl_library.EC_KEY_free(k)
        return PublicKey(PublicKey.compress(public_key) if compressed else public_key)

    @staticmethod
    def create_new(label=''):
        k = ssl_library.EC_KEY_new_by_curve_name(NID_secp256k1)
    
        if ssl_library.EC_KEY_generate_key(k) != 1:
            raise Exception("internal error")
    
        bignum_private_key = ssl_library.EC_KEY_get0_private_key(k)
        size = (ssl_library.BN_num_bits(bignum_private_key)+7)//8
    
        storage = ctypes.create_string_buffer(size)
        ssl_library.BN_bn2bin(bignum_private_key, storage)
        private_key = storage.raw
    
        if (len(private_key) == size) and size < 32:
            private_key = bytes([0] * (32 - size)) + private_key
    
        ssl_library.EC_KEY_free(k)

        return PrivateKey(private_key)

    def serialize(self):
        return self.secret

    @staticmethod
    def unserialize(data):
        secret = data[:32]
        if len(secret) < 32:
            raise SerializeDataTooShort()
        return PrivateKey(secret), data[32:]

