import ctypes
import threading

from .serialize import Serialize, SerializeDataTooShort
from .util import *

try:
    ssl_library = ctypes.cdll.LoadLibrary('libeay32.dll')
except:
    ssl_library = ctypes.cdll.LoadLibrary('libssl.so')

ssl_library.EC_KEY_new.restype = ctypes.c_void_p
ssl_library.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p

CRYPTO_LOCK = 1

NID_secp256k1 = 714
secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

class PublicKey:
    '''Also an ECC point'''

    def __init__(self, pubkey):
        assert len(pubkey) in (33, 65) and pubkey[0] in (0x02, 0x03, 0x04)
        self.pubkey = pubkey

    def __hash__(self):
        return int.from_bytes(self.pubkey, 'big')

    def __eq__(self, other):
        return self is other or (self.pubkey == other.pubkey)

    def __lt__(self, other):
        return self.pubkey < other.pubkey

    def add_constant(self, c):
        '''this + c * generator'''
        k = ssl_library.EC_KEY_new_by_curve_name(NID_secp256k1)
        
        group = ssl_library.EC_KEY_get0_group(k)
        point = ssl_library.EC_POINT_new(group)

        # int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
        #     const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
        # 
        # int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
        #     const BIGNUM *x, int y_bit, BN_CTX *ctx);

        if self.is_compressed():
            x_storage = ctypes.create_string_buffer(self.pubkey[1:33])
            bignum_x_coordinate = ssl_library.BN_new()
            ssl_library.BN_bin2bn(x_storage, 32, bignum_x_coordinate)

            bignum_y_coordinate = None

            r = ssl_library.EC_POINT_set_compressed_coordinates_GFp(group, point, bignum_x_coordinate, self.pubkey[0] & 0x01, None)
        else:
            x_storage = ctypes.create_string_buffer(self.pubkey[1:33])
            bignum_x_coordinate = ssl_library.BN_new()
            ssl_library.BN_bin2bn(x_storage, 32, bignum_x_coordinate)

            y_storage = ctypes.create_string_buffer(self.pubkey[33:65])
            bignum_y_coordinate = ssl_library.BN_new()
            ssl_library.BN_bin2bn(y_storage, 32, bignum_y_coordinate)

            r = ssl_library.EC_POINT_set_affine_coordinates(group, point, bignum_x_coordinate, bignum_y_coordinate, None)

        # Load c into BIGNUM
        storage = ctypes.create_string_buffer(int.to_bytes(c, 32, 'big'))
        bignum_c = ssl_library.BN_new()
        ssl_library.BN_bin2bn(storage, 32, bignum_c)

        # Load 1 into BIGNUM
        storage_one = ctypes.create_string_buffer(int.to_bytes(1, 32, 'big'))
        bignum_one = ssl_library.BN_new()
        ssl_library.BN_bin2bn(storage_one, 32, bignum_one)

        # result = generator * bignum_c + self
        result = ssl_library.EC_POINT_new(group)
        ssl_library.EC_POINT_mul(group, result, bignum_c, point, bignum_one, None)

        # Load the point into our EC_KEY and extract it
        ssl_library.EC_KEY_set_public_key(k, result)
        size = ssl_library.i2o_ECPublicKey(k, 0)
        result_storage = ctypes.create_string_buffer(size)
        pointer_result_storage = ctypes.pointer(result_storage)
        ssl_library.i2o_ECPublicKey(k, ctypes.byref(pointer_result_storage))
        public_key = result_storage.raw

        ssl_library.EC_POINT_free(result)
        ssl_library.BN_free(bignum_one)
        ssl_library.BN_free(bignum_c)
        ssl_library.BN_free(bignum_x_coordinate)
        if bignum_y_coordinate is not None:
            ssl_library.BN_free(bignum_y_coordinate)
        ssl_library.EC_POINT_free(point)
        ssl_library.EC_KEY_free(k)

        return PublicKey(PublicKey.compress(public_key)) if self.is_compressed() else PublicKey(public_key)

    def multiply(self, c):
        k = ssl_library.EC_KEY_new_by_curve_name(NID_secp256k1)
        
        group = ssl_library.EC_KEY_get0_group(k)
        point = ssl_library.EC_POINT_new(group)

        # int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
        #     const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
        # 
        # int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
        #     const BIGNUM *x, int y_bit, BN_CTX *ctx);

        if self.is_compressed():
            x_storage = ctypes.create_string_buffer(self.pubkey[1:33])
            bignum_x_coordinate = ssl_library.BN_new()
            ssl_library.BN_bin2bn(x_storage, 32, bignum_x_coordinate)

            bignum_y_coordinate = None

            r = ssl_library.EC_POINT_set_compressed_coordinates_GFp(group, point, bignum_x_coordinate, self.pubkey[0] & 0x01, None)
        else:
            x_storage = ctypes.create_string_buffer(self.pubkey[1:33])
            bignum_x_coordinate = ssl_library.BN_new()
            ssl_library.BN_bin2bn(x_storage, 32, bignum_x_coordinate)

            y_storage = ctypes.create_string_buffer(self.pubkey[33:65])
            bignum_y_coordinate = ssl_library.BN_new()
            ssl_library.BN_bin2bn(y_storage, 32, bignum_y_coordinate)

            r = ssl_library.EC_POINT_set_affine_coordinates(group, point, bignum_x_coordinate, bignum_y_coordinate, None)

        # Load c into BIGNUM
        storage = ctypes.create_string_buffer(int.to_bytes(c, 32, 'big'))
        bignum_c = ssl_library.BN_new()
        ssl_library.BN_bin2bn(storage, 32, bignum_c)

        # Multiply point * c
        result = ssl_library.EC_POINT_new(group)
        ssl_library.EC_POINT_mul(group, result, None, point, bignum_c, None)

        # Load the point into our EC_KEY and extract it
        ssl_library.EC_KEY_set_public_key(k, result)
        size = ssl_library.i2o_ECPublicKey(k, 0)
        result_storage = ctypes.create_string_buffer(size)
        pointer_result_storage = ctypes.pointer(result_storage)
        ssl_library.i2o_ECPublicKey(k, ctypes.byref(pointer_result_storage))
        public_key = result_storage.raw

        ssl_library.EC_POINT_free(result)
        ssl_library.BN_free(bignum_c)
        ssl_library.BN_free(bignum_x_coordinate)
        if bignum_y_coordinate is not None:
            ssl_library.BN_free(bignum_y_coordinate)
        ssl_library.EC_POINT_free(point)
        ssl_library.EC_KEY_free(k)

        return PublicKey(PublicKey.compress(public_key)) if self.is_compressed() else PublicKey(public_key)

    def is_compressed(self):
        return self.pubkey[0] in (0x02, 0x03) and len(self.pubkey) == 33

    def as_hex(self):
        return bytes_to_hexstring(self.pubkey, reverse=False)

    def as_address(self, coin):
        return base58_check(coin, coin.hash160(self.pubkey), version_bytes=coin.ADDRESS_VERSION_BYTES)

    def as_hash160(self, coin):
        return coin.hash160(self.pubkey)

    @staticmethod
    def compress(pubkey):
        if pubkey[0] in (0x02, 0x03):
            return pubkey
        assert pubkey[0] == 0x04
        x_coord = pubkey[1:33]
        if pubkey[64] & 0x01:
            c = bytes([0x03]) + x_coord
        else:
            c = bytes([0x02]) + x_coord
        return c

    @staticmethod
    def from_hex(s):
        pubkey = hexstring_to_bytes(s, reverse=False)
        return PublicKey(pubkey)

class PrivateKey:
    def __init__(self, secret):
        self.secret = secret

    def __hash__(self):
        return int.from_bytes(self.secret, 'big')

    def __eq__(self, other):
        return self is other or (self.__class__ is other.__class__ and self.secret == other.secret)

    def as_wif(self, coin, compressed):
        '''WIF - wallet import format'''
        return base58_check(coin, self.secret + (b'\x01' if compressed else b''), version_bytes=coin.PRIVATE_KEY_VERSION_BYTES)

    def as_int(self):
        return int.from_bytes(self.secret, 'big')

    def add_constant(self, c):
        r = (int.from_bytes(self.secret, 'big') + c) % secp256k1_order
        return PrivateKey(int.to_bytes(r, 32, 'big'))

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

    def sign(self, hash):
        k = ssl_library.EC_KEY_new_by_curve_name(NID_secp256k1)
        
        storage = ctypes.create_string_buffer(self.secret)
        bignum_private_key = ssl_library.BN_new()
        ssl_library.BN_bin2bn(storage, 32, bignum_private_key)

        group = ssl_library.EC_KEY_get0_group(k)
        point = ssl_library.EC_POINT_new(group)

        ssl_library.EC_POINT_mul(group, point, bignum_private_key, None, None, None)
        ssl_library.EC_KEY_set_private_key(k, bignum_private_key)
        ssl_library.EC_KEY_set_public_key(k, point)

        assert isinstance(hash, bytes)
        dgst = ctypes.cast((ctypes.c_ubyte*len(hash))(*[int(x) for x in hash]), ctypes.POINTER(ctypes.c_ubyte))

        siglen = ctypes.c_int(ssl_library.ECDSA_size(k))
        signature = ctypes.create_string_buffer(siglen.value)
        if ssl_library.ECDSA_sign(0, dgst, len(hash), signature, ctypes.byref(siglen), k) == 0:
            raise Exception("internal error: failed to sign")

        signature = signature.raw[:siglen.value]

        ssl_library.EC_POINT_free(point)
        ssl_library.BN_free(bignum_private_key)
        ssl_library.EC_KEY_free(k)

        return signature

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


openssl_locks = [threading.Lock() for _ in range(ssl_library.CRYPTO_num_locks())]
openssl_locking_function = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
openssl_threadid_function = ctypes.CFUNCTYPE(ctypes.c_ulong)

@openssl_locking_function
def openssl_lock(mode, type, file, line):
    if (mode & CRYPTO_LOCK) != 0:
        openssl_locks[type].acquire()
    else:
        openssl_locks[type].release()

@openssl_threadid_function
def openssl_threadid():
    v = threading.current_thread().ident
    return v

ssl_library.CRYPTO_set_id_callback(openssl_threadid)
ssl_library.CRYPTO_set_locking_callback(openssl_lock)

