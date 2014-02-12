import struct
from .. import base58

from .basemonitor import BaseMonitor

from ..script import *
from ..serialize import Serialize
from ..transaction import TransactionOutput, TransactionPrevOut
from ..util import *
from ..wallet import InvalidAddress, Spend

class MultisigScriptHashSpend(Spend):
    def __init__(self, coin, category, amount, address, prevout, script, address_info, spent_in=None):
        Spend.__init__(self, coin, category, amount)

        self.prevout = prevout
        self.script = script
        self.address = address
        self.address_info = address_info
        self.spent_in = set([] if spent_in is None else spent_in)

    def hash(self):
        '''one spend is equal to another only based on the prevout value'''
        return self.coin.hash(self.prevout.serialize())

    def is_spent(self):
        return len(self.spent_in) != 0

    def is_spendable(self, spv):
        # TODO check spent_in txids to see if any haven't confirmed for a while and allow respending after some time?
        return not self.is_spent() and self.get_confirmations(spv) >= self.coin.TRANSACTION_CONFIRMATION_DEPTH

    def get_confirmations(self, spv):
        return spv.txdb.get_tx_depth(self.prevout.tx_hash)
        
    def create_input_creators(self, spv):
        pksic = PubKeySpendInputCreator(spv, self.prevout, self.script, 0xffffffff, self.address_info)
        return [pksic]

    def serialize(self):
        return Serialize.serialize_string(self.category) + Serialize.serialize_variable_int(self.amount) + \
               self.prevout.serialize() + Serialize.serialize_string(self.address) + \
               struct.pack('<L', len(self.script)) + self.script + \
               Serialize.serialize_dict(self.address_info) + \
               Serialize.serialize_list(list(self.spent_in))

    @staticmethod
    def unserialize(data, coin):
        category, data = Serialize.unserialize_string(data)
        amount, data = Serialize.unserialize_variable_int(data)
        prevout, data = TransactionPrevOut.unserialize(data)
        address, data = Serialize.unserialize_string(data)

        script_length = struct.unpack("<L", data[:4])[0]
        script = data[4:4+script_length]

        address_info, data = Serialize.unserialize_dict(data[4+script_length:])

        spent_in, data = Serialize.unserialize_list(data)

        spends = MultisigScriptHashSpend(coin, category, amount, address, prevout, script, address_info, spent_in=spent_in)
        return spends, data

    def __str__(self):
        return '<MultisigScriptHashSpend {} BTC prevout={} address={}{}>'.format(self.coin.format_money(self.amount), str(self.prevout), self.address, ' SPENT' if len(self.spent_in) else '')


class MultisigScriptHashPaymentMonitor(BaseMonitor):
    spend_classes = [MultisigScriptHashSpend]

    def __init__(self, spv):
        BaseMonitor.__init__(self, spv)
        self.prevouts = {}
        self.script_addresses = {}

    def on_spend(self, wallet, spend):
        if not isinstance(spend, MultisigScriptHashSpend):
            # We only care about script hash spends
            return

        # TODO check if spend.redemption_script is a multisig redemption script

        # Save spend to check if it gets spent
        self.prevouts[spend.prevout] = spend

    def on_redemption_script(self, wallet, redemption_script, metadata):
        address = base58_check(self.spv.coin, self.spv.coin.hash160(redemption_script), version_bytes=self.spv.coin.P2SH_ADDRESS_VERSION_BYTES)

        # TODO parse redemption_script for nreq, check if we own enough pubkeys to sign for it, etc
        # TODO on_public_key should check if any of our redemption_scripts reference that pubkey and if a private key is available for signing, etc

        self.script_addresses[address] = {
            'address'          : address,
            'redemption_script': bytes_to_hexstring(redemption_script, reverse=False),
        }

        wallet.add_temp('address', address, {'redemption_script': redemption_script})

        print('[MULTISIGSCRIPTHASHPAYMENTMONITOR] watching for script-hash payment to {}'.format(address))

    def on_tx(self, tx):
        tx_saved = False
        tx_hash = tx.hash()

        # check inputs, they might spend coins from the wallet
        for i, input in enumerate(tx.inputs):
            pass

        for i, output in enumerate(tx.outputs):
            script = output.script.program

            if len(script) == 23 and script[0] == OP_HASH160 and script[1] == 20 and script[-1] == OP_EQUAL:
                redemption_script_hash = script[2:22]
            else:
                continue

            address = base58_check(self.spv.coin, redemption_script_hash, version_bytes=self.spv.coin.P2SH_ADDRESS_VERSION_BYTES)
            address_info = self.script_addresses.get(address, None)
            if address_info is None:
                continue

            self.spv.txdb.save_tx(tx)

            # We care about this payment
            # TODO - distinguish between the ones we can/can't spend
            prevout = TransactionPrevOut(tx_hash, i)
            spend = MultisigScriptHashSpend(self.spv.coin, 'default', output.amount, address, prevout, script, address_info)
            if self.spv.wallet.add_spend(spend):
                #! unknown_spend_key = (tx_hash, i)
                #! unknown_spend_metadata = self.spv.wallet.get('unknown_spend', unknown_spend_key)
                #! if unknown_spend_metadata is not None:
                #!     for tx_hash in unknown_spend_metadata['spent_in']:
                #!         # this spend is spent already
                #!         spend.spent_in.add(tx_hash)
                #!     self.wallet.update_spend(spend)
                    
                if self.spv.logging_level <= INFO:
                    print('[MULTISIGSCRIPTHASHPAYMENTMONITOR] processed payment of {} to {}'.format(output.amount, address))
            else:
                if self.spv.logging_level <= DEBUG:
                    print('[MULTISIGSCRIPTHASHPAYMENTMONITOR] payment of {} to {} already seen'.format(output.amount, address))

