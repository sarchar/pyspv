import struct

from .basemonitor import BaseMonitor
from ..serialize import Serialize
from ..transaction import TransactionPrevOut
from ..wallet import Spend

from ..script import *
from ..util import *

class PubKeySpend(Spend):
    def __init__(self, coin, category, amount, address, prevout, script, address_info):
        Spend.__init__(self, coin, category, amount)

        self.prevout = prevout
        self.script = script
        self.address = address
        self.address_info = address_info

    def destination_name(self):
        return self.address

    def is_spendable(self):
        return self.get_confirmations() >= 6

    def get_confirmations(self, spv):
        # TODO
        # return spv.blockchain.get_best_chain_height() - get_best_block_height_containing(self.prevout.tx_hash)
        return 0
        
    def create_inputs(self):
        # TODO - returns list of PubKeySpendInputs, which individually sign an input (at this point, not all inputs/outputs are determined so
        # can't do signing yet)
        return []

    def serialize(self):
        return Serialize.serialize_string(self.category) + Serialize.serialize_variable_int(self.amount) + \
               self.prevout.serialize() + Serialize.serialize_string(self.address) + \
               struct.pack('<L', len(self.script)) + self.script + \
               Serialize.serialize_dict(self.address_info)

    @staticmethod
    def unserialize(data, coin):
        category, data = Serialize.unserialize_string(data)
        amount, data = Serialize.unserialize_variable_int(data)
        prevout, data = TransactionPrevOut.unserialize(data)
        address, data = Serialize.unserialize_string(data)

        script_length = struct.unpack("<L", data[:4])[0]
        script = data[4:4+script_length]

        address_info, data = Serialize.unserialize_dict(data[4+script_length:])

        spends = PubKeySpend(coin, category, amount, address, prevout, script, address_info)
        return spends, data

class PubKeyPaymentMonitor(BaseMonitor):
    spend_classes = [PubKeySpend]

    def __init__(self, spv):
        BaseMonitor.__init__(self, spv)
        self.pubkey_addresses = {}
        self.prevouts = {}

    def on_spend(self, wallet, spend):
        if not isinstance(spend, PubKeySpend):
            return

        # Save spend to check if it gets spent
        self.prevouts[spend.prevout] = spend

    def on_private_key(self, wallet, private_key, metadata):
        public_key = private_key.get_public_key(False)
        address = public_key.as_address(self.spv.coin)

        self.pubkey_addresses[address] = {
            'address'       : address,
            'public_key_hex': public_key.as_hex(self.spv.coin),
        }

        wallet.add_temp('public_key', public_key, {'private_key': private_key})

        if self.spv.logging_level <= DEBUG:
            print('[PUBKEYPAYMENTS] watching for payments to {}'.format(address))

        public_key = private_key.get_public_key(True)
        address = public_key.as_address(self.spv.coin)

        self.pubkey_addresses[address] = {
            'address'       : address,
            'public_key_hex': public_key.as_hex(self.spv.coin),
        }

        wallet.add_temp('public_key', public_key, {'private_key': private_key})

        if self.spv.logging_level <= DEBUG:
            print('[PUBKEYPAYMENTS] watching for payments to {}'.format(address))


    def on_tx(self, tx):
        tx_saved = False

        if self.spv.txdb.has_tx(tx.hash()):
            # We've seen this tx before.  Done.
            return

        # TODO - check inputs, they might spend coins from the wallet
        for i, input in enumerate(tx.inputs):
            spend = self.prevouts.get(input.prevout, None)
            if spend is None:
                continue
            # TODO - this spend is spent!

        for i, output in enumerate(tx.outputs):
            script = output.script.program

            if len(script) == 25 and script[0] == OP_DUP \
                         and script[1] == OP_HASH160 and script[2] == 20 \
                         and script[23] == OP_EQUALVERIFY and script[24] == OP_CHECKSIG:
                # Pay-to-pubkey-hash
                address = base58_check(self.spv.coin, script[3:23], version_bytes=self.spv.coin.ADDRESS_VERSION_BYTES)
            elif len(script) in (35, 67) and script[0] in (33, 65) and \
                         script[0] == (len(script) - 2) and script[-1] == OP_CHECKSIG:
                # Pay-to-pubkey
                address = base58_check(self.spv.coin, self.spv.coin.hash160(script[1:-1]), version_bytes=self.spv.coin.ADDRESS_VERSION_BYTES)
            else:
                # Not a pubkey payment
                continue

            address_info = self.pubkey_addresses.get(address, None)
            if address_info is not None:
                prevout = TransactionPrevOut(tx.hash(), i)
                spend = PubKeySpend(self.spv.coin, 'default', output.amount, address, prevout, script, address_info)
                if self.spv.wallet.add_spend(spend):
                    if self.spv.logging_level <= INFO:
                        print('[PUBKEYPAYMENTMONITOR] processed payment of {} to {}'.format(output.amount, address))
                    if not tx_saved:
                        self.spv.txdb.save_tx(tx)
                        tx_saved = True
                else:
                    if self.spv.logging_level <= DEBUG:
                        print('[PUBKEYPAYMENTMONITOR] payment of {} to {} already seen'.format(output.amount, address))

