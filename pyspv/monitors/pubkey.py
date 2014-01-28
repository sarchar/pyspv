import struct

from .payment import BaseMonitor
from ..serialize import Serialize
from ..transaction import TransactionPrevOut
from ..wallet import Spend

from ..script import *
from ..util import *

class PubKeySpend(Spend):
    def __init__(self, amount, address, prevout, script, watch):
        Spend.__init__(self, amount)

        self.prevout = prevout
        self.script = script
        self.address = address
        self.watch = watch

    def destination_name(self):
        return self.address

    def add_inputs(self, tx, sign_flags):
        # TODO
        return []

    def serialize(self):
        return Serialize.serialize_variable_int(self.amount) + \
               self.prevout.serialize() + Serialize.serialize_string(self.address) + \
               struct.pack('<L', len(self.script)) + self.script + \
               Serialize.serialize_dict(self.watch)

    @staticmethod
    def unserialize(data):
        amount, data = Serialize.unserialize_variable_int(data)
        prevout, data = TransactionPrevOut.unserialize(data)
        address, data = Serialize.unserialize_string(data)

        script_length = struct.unpack("<L", data[:4])[0]
        script = data[4:4+script_length]

        watch, data = Serialize.unserialize_dict(data[4+script_length:])

        spends = SimpleSpend(amount, address, prevout, script, watch)
        return spends, data

class PubKeyPaymentMonitor(BaseMonitor):
    spend_class = PubKeySpend

    def __init__(self, spv):
        BaseMonitor.__init__(self, spv)
        self.pubkey_addresses = {}

    def on_private_key(self, private_key, metadata):
        address = private_key.get_public_key(False).as_address(self.spv.coin)
        if self.spv.logging_level <= DEBUG:
            print('[PUBKEYPAYMENTS] watching for payments to {}'.format(address))

        self.pubkey_addresses[address] = {
            'compressed': False,
        }

        address = private_key.get_public_key(True).as_address(self.spv.coin)
        if self.spv.logging_level <= DEBUG:
            print('[PUBKEYPAYMENTS] watching for payments to {}'.format(address))

        self.pubkey_addresses[address] = {
            'compressed': True,
        }

    def on_tx(self, tx):
        save_tx = False

        if self.spv.txdb.has_tx(tx.hash()):
            # We've seen this tx before.  Done.
            return

        for i, output in enumerate(tx.outputs):
            script = output.script.program

            if len(script) == 25 and script[0] == OP_DUP \
                         and script[1] == OP_HASH160 and script[2] == 20 \
                         and script[23] == OP_EQUALVERIFY and script[24] == OP_CHECKSIG:
                address = base58_check(self.spv.coin, script[3:23], version_bytes=self.spv.coin.ADDRESS_VERSION_BYTES)
            elif len(script) in (35, 67) and script[0] in (33, 65) and \
                         script[0] == (len(script) - 2) and script[-1] == OP_CHECKSIG:
                address = base58_check(self.spv.coin, self.spv.coin.hash160(script[1:-1]), version_bytes=self.spv.coin.ADDRESS_VERSION_BYTES)
            else:
                # Not simple payment
                continue

            watch = self.pubkey_addresses.get(address, None)
            if watch is not None:
                if self.spv.logging_level <= DEBUG:
                    print('[SIMPLEPAYMENTS] payment of {} to {} received'.format(output.amount, address))

                prevout = TransactionPrevOut(tx.hash(), i)
                spend = SimpleSpend(output.amount, address, prevout, script, watch)
                self.spv.wallet.add_spend(self, spend)
                save_tx = True

        if save_tx:
            self.spv.txdb.save_tx(tx)

        # TODO - check inputs, they might spend coins from the wallet

