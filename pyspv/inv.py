import struct

from .serialize import SerializeDataTooShort, Serialize

class INV:
    MSG_ERROR = 0
    MSG_TX    = 1
    MSG_BLOCK = 2

    def __init__(self, type=MSG_ERROR, hash=None):
        self.hash = hash
        self.type = type

    @staticmethod
    def unserialize(data):
        if len(data) < 36:
            raise SerializeDataTooShort()

        type = struct.unpack("<L", data[:4])[0]
        return INV(type=type, hash=data[4:36]), data[36:]

