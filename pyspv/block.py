import struct

from .serialize import Serialize
from .util import *
from .transaction import Transaction

class BadSerializedBlock(Exception):
    pass

class BlockHeader:
    CURRENT_VERSION = 1

    def __init__(self, coin, version=CURRENT_VERSION, prev_block_hash=(b'\x00' * 32), merkle_root_hash=(b'\x00' * 32), timestamp=0, bits=0, nonce=0):
        self.version = version
        self.prev_block_hash = prev_block_hash
        self.merkle_root_hash = merkle_root_hash
        self.timestamp = timestamp if timestamp is not None else 0
        self.bits = bits
        self.nonce = nonce
        self.coin = coin

    def check(self):
        target = bits_to_target(self.bits)
        if target <= 0 or target > Block.BLOCK_DIFFICULTY_LIMIT:
            return False
        return int.from_bytes(self.hash(), 'little') <= target

    def work(self):
        target = bits_to_target(self.bits)
        if target <= 0:
            return 0
        return (1 << 256) // (target + 1)

    def hash(self):
        return self.coin.hash(self.serialize())

    def serialize(self):
        version = struct.pack("<L", self.version)
        extra   = struct.pack("<LLL", self.timestamp, self.bits, self.nonce)
        return version + self.prev_block_hash + self.merkle_root_hash + extra

    def serialize_size(self):
        return 4 + 32 + 32 + 12

    @staticmethod
    def unserialize(data, coin):
        version = struct.unpack("<L", data[:4])[0]
        prev_block_hash = data[4:36]
        merkle_root_hash = data[36:68]
        timestamp, bits, nonce = struct.unpack("<LLL", data[68:80])

        header = BlockHeader(coin, version=version, prev_block_hash=prev_block_hash, merkle_root_hash=merkle_root_hash, timestamp=timestamp, bits=bits, nonce=nonce)
        return header, data[80:]

    def __str__(self):
        return '<blockheader {}\n\tversion={}\n\tprev_block_hash={}\n\tmerkle_root_hash={}\n\ttimestamp={}\n\tbits={:08x}\n\tnonce={}\n\ttarget={:064x}\n\tvalid={}>'.format \
            (bytes_to_hexstring(self.hash()), self.version, bytes_to_hexstring(self.prev_block_hash), bytes_to_hexstring(self.merkle_root_hash),
             self.timestamp, self.bits, self.nonce, bits_to_target(self.bits), self.check())

class Block:
    BLOCK_DIFFICULTY_LIMIT = ((1 << 256) - 1) >> 32
    assert target_to_bits(BLOCK_DIFFICULTY_LIMIT) == 0x1d00ffff

    def __init__(self, coin, header=None, transactions=None, previous_block=None):
        self.coin = coin
        self.header = BlockHeader(coin) if header is None else header
        self.transactions = [] if transactions is None else transactions

        self.previous_block = previous_block
        self.connected = previous_block is not None and previous_block.connected

    def check(self):
        if len(self.transactions) == 0 or self.serialize_size() > self.coin.MAX_BLOCK_SIZE:
            return False

        if not self.header.check() or not self.header.merkle_root_hash == self.calculate_merkle_root():
            return False

        if not self.transactions[0].is_coinbase():
            return False

        if not all(not tx.is_coinbase() for tx in self.transactions[1:]):
            return False

        # We can't verify transactions inputs because we don't have a full UTXO set to check against.

        return True

    def calculate_merkle_root(self):
        hashes = [tx.hash() for tx in self.transactions]

        while len(hashes) != 1:
            if (len(hashes) % 2) == 1:
                hashes.append(hashes[-1])
            new_hashes = []
            for i in range(0, len(hashes), 2):
                k = hashes[i] + hashes[i+1]
                new_hashes.append(self.coin.hash(k))
            hashes = new_hashes

        return hashes[0]

    @staticmethod
    def unserialize(data, coin):
        header, data = BlockHeader.unserialize(data, coin)

        num_transactions, data = Serialize.unserialize_variable_int(data)
        transactions = []
        for i in range(num_transactions):
            try:
                tx, data = Transaction.unserialize(data, coin)
            except:
                raise BadSerializedBlock("block {} couldn't unserialize because transaction {} failed to unserialize".format(bytes_to_hexstring(header.hash()), i))
            transactions.append(tx)

        block = Block(coin, header=header, transactions=transactions)
        return block, data

    def serialize(self):
        data_list = []
        data_list.append(self.header.serialize())
        data_list.append(Serialize.serialize_variable_int(len(self.transactions)))

        for tx in self.transactions:
            data_list.append(tx.serialize())

        return b''.join(data_list)

    def serialize_size(self):
        data_size = 0
        data_size += self.header.serialize_size()
        data_size += Serialize.serialize_variable_int_size(len(self.transactions))

        for tx in self.transactions:
            data_size += tx.serialize_size()

        return data_size

    def __str__(self):
        return '<block {} ntx={}>'.format(bytes_to_hexstring(self.header.hash()), len(self.transactions))


