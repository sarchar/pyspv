import hashlib
from bitarray import bitarray

class Bloom:
    def __init__(self, size, hash_count):
        self.d = bitarray(size)
        self.n = hash_count
        self.s = size

    def add(self, data):
        self.d[int.from_bytes(data, 'little') % self.s] = 1

        for _ in range(self.n):
            hasher = hashlib.sha256()
            hasher.update(data)
            data = hasher.digest()
            self.d[int.from_bytes(data, 'little') % self.s] = 1

    def has(self, data):
        if self.d[int.from_bytes(data, 'little') % self.s] != 1:
            return False

        for _ in range(self.n):
            hasher = hashlib.sha256()
            hasher.update(data)
            data = hasher.digest()
            if self.d[int.from_bytes(data, 'little') % self.s] != 1:
                return False

        return True

