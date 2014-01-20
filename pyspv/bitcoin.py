import hashlib

class Bitcoin:
    ADDRESS_VERSION_BYTES     = b'\x00'
    PRIVATE_KEY_VERSION_BYTES = b'\x80'

    @staticmethod
    def hash(data):
        hasher = hashlib.sha256()
        hasher.update(data)
        hasher2 = hashlib.sha256()
        hasher2.update(hasher.digest())
        return hasher2.digest()

    @staticmethod
    def hash160(data):
        hasher = hashlib.sha256()
        hasher.update(data)
        hasher2 = hashlib.new('ripemd160')
        hasher2.update(hasher.digest())
        return hasher2.digest()

class BitcoinTestnet(Bitcoin):
    ADDRESS_VERSION_BYTES     = b'\x6f'
    PRIVATE_KEY_VERSION_BYTES = bytes([0x6f + 0x80])

