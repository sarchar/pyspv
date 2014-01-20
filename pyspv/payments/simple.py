import struct

from .payments import BasePayments
from ..serialize import Serialize
from ..transaction import TransactionPrevOut
from ..wallet import Coins

from ..script import *
from ..util import *

class SimpleCoins(Coins):
    def __init__(self, amount, address, prevout, scriptPubKey, watch):
        Coins.__init__(self, amount)

        self.prevout = prevout
        self.scriptPubKey = scriptPubKey
        self.address = address
        self.watch = watch

    def destination_name(self):
        return self.address

    def produce_inputs(self, tx, sign_flags):
        # TODO
        return []

    def serialize(self):
        return Serialize.serialize_variable_int(self.amount) + \
               self.prevout.serialize() + Serialize.serialize_string(self.address) + \
               struct.pack('<L', len(self.scriptPubKey)) + self.scriptPubKey + \
               Serialize.serialize_dict(self.watch)

    @staticmethod
    def unserialize(data):
        amount, data = Serialize.unserialize_variable_int(data)
        prevout, data = TransactionPrevOut.unserialize(data)
        address, data = Serialize.unserialize_string(data)

        scriptPubKeyLength = struct.unpack("<L", data[:4])[0]
        scriptPubKey = data[4:4+scriptPubKeyLength]

        watch, data = Serialize.unserialize_dict(data[4+scriptPubKeyLength:])

        coins = SimpleCoins(amount, address, prevout, scriptPubKey, watch)
        return coins, data

class SimplePayments(BasePayments):
    name = 'simple_payments'
    coins = SimpleCoins

    def __init__(self, spv):
        BasePayments.__init__(self, spv)

        self.watch_addresses = {}

        # Loop over all private keys, and build a set of bitcoin addresses
        for i, e in enumerate(self.spv.wallet.private_keys()):
            pk, label = e
            self.add_key(pk, i)

    def add_key(self, pk, i):
        address = pk.get_public_key(False).as_address(self.spv.coin)
        if self.spv.logging_level <= DEBUG:
            print('[SIMPLEPAYMENTS] watching for payments to {}'.format(address))
        self.watch_addresses[address] = {
            'compressed': False,
            'key_index' : i,
        }

        address = pk.get_public_key(True).as_address(self.spv.coin)
        if self.spv.logging_level <= DEBUG:
            print('[SIMPLEPAYMENTS] watching for payments to {}'.format(address))
        self.watch_addresses[address] = {
            'compressed': True,
            'key_index' : i,
        }

    def on_tx(self, tx):
        for i, output in enumerate(tx.outputs):
            scriptPubKey = output.scriptPubKey.program

            if len(scriptPubKey) == 25 and scriptPubKey[0] == OP_DUP \
                         and scriptPubKey[1] == OP_HASH160 and scriptPubKey[2] == 20 \
                         and scriptPubKey[23] == OP_EQUALVERIFY and scriptPubKey[24] == OP_CHECKSIG:
                address = base58_check(self.spv.coin, scriptPubKey[3:23], version_bytes=self.spv.coin.ADDRESS_VERSION_BYTES)
            elif len(scriptPubKey) in (35, 67) and scriptPubKey[0] in (33, 65) and \
                         scriptPubKey[0] == (len(scriptPubKey) - 2) and scriptPubKey[-1] == OP_CHECKSIG:
                address = base58_check(self.spv.coin, self.spv.coin.hash160(scriptPubKey[1:-1]), version_bytes=self.spv.coin.ADDRESS_VERSION_BYTES)
            else:
                # Not simple payment
                continue

            watch = self.watch_addresses.get(address, None)
            if watch is not None:
                if self.spv.logging_level <= DEBUG:
                    print('[SIMPLEPAYMENTS] payment of {} to {} received'.format(output.amount, address))

                prevout = TransactionPrevOut(tx.hash(), i)
                coins = SimpleCoins(output.amount, address, prevout, scriptPubKey, watch)
                self.spv.wallet.add_coins(self, coins)

        # TODO - check inputs, they might spend coins from the wallet

