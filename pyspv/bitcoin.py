import hashlib

class Bitcoin:
    @staticmethod
    def hash(data):
        hasher = hashlib.sha256()
        hasher.update(data)
        hasher2 = hashlib.sha256()
        hasher2.update(hasher.digest())
        return hasher2.digest()

