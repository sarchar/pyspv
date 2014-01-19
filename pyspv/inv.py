import struct

from .serialize import SerializeDataTooShort, Serialize
from .util import *

class Inv:
    MSG_ERROR = 0
    MSG_TX    = 1
    MSG_BLOCK = 2

    def __init__(self, type=MSG_ERROR, hash=None):
        self.hash = hash
        self.type = type

    def __eq__(self, other):
        return self.hash == other.hash and self.type == other.type

    def __hash__(self):
        if self.hash is None:
            return 0
        return int.from_bytes(self.hash, 'little')

    def __str__(self):
        return '<inv {} {}>'.format(
                { Inv.MSG_ERROR: 'error',
                  Inv.MSG_TX   : 'tx',
                  Inv.MSG_BLOCK: 'block' }[self.type],
                bytes_to_hexstring(self.hash)
                )

    def serialize(self):
        assert self.hash is not None, "cannot serialize"
        return struct.pack("<L", self.type) + self.hash

    @staticmethod
    def unserialize(data):
        if len(data) < 36:
            raise SerializeDataTooShort()

        type = struct.unpack("<L", data[:4])[0]
        return Inv(type=type, hash=data[4:36]), data[36:]

