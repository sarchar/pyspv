import struct

from .basemonitor import BaseMonitor
from .. import base58
from ..keys import PrivateKey, PublicKey
from ..serialize import Serialize
from ..transaction import TransactionPrevOut, TransactionOutput, TransactionInput
from ..transactionbuilder import TransactionBuilder
from ..wallet import InvalidAddress, Spend

from ..script import *
from ..util import *

class PubKeyTransactionBuilder(TransactionBuilder):
    def __init__(self, *args, **kwargs):
        TransactionBuilder.__init__(self, *args, **kwargs)
        
    def add_recipient(self, address, amount):
        assert isinstance(amount, int), "amount must be in satoshis"
        coin = self.wallet.spv.coin

        address_bytes = int.to_bytes(base58.decode(address), coin.ADDRESS_BYTE_LENGTH, 'big')
        k = len(coin.ADDRESS_VERSION_BYTES)
        if address_bytes[:k] != coin.ADDRESS_VERSION_BYTES:
            raise InvalidAddress("Address version is incorrect")

        address_hash = coin.hash(address_bytes[:-4])
        if address_hash[:4] != address_bytes[-4:]:
            raise InvalidAddress("Address checksum is incorrect")

        script = Script()
        script.push_op(OP_DUP)
        script.push_op(OP_HASH160)
        script.push_bytes(address_bytes[k:-4])
        script.push_op(OP_EQUALVERIFY)
        script.push_op(OP_CHECKSIG)

        self.add_output(amount=amount, script=script)

    def create_change_script(self):
        change_private_key = PrivateKey.create_new()
        change_address = change_private_key.get_public_key(True).as_hash160(self.wallet.spv.coin)

        change_script = Script()
        change_script.push_op(OP_DUP)
        change_script.push_op(OP_HASH160)
        change_script.push_bytes(change_address)
        change_script.push_op(OP_EQUALVERIFY)
        change_script.push_op(OP_CHECKSIG)

        return change_private_key, change_script

class PubKeySpendInputCreator:
    '''Input creators need to define the following class values:
        self.prevout : a TransactionPrevOut
        self.script  : a byte sequence for scriptPubKey
        self.sequence: the input sequence number

        Everything else can be class-specific, but the above are used for serialization and signing
    '''

    def __init__(self, spv, prevout, script, sequence, address_info):
        self.spv = spv
        self.prevout = prevout
        self.script = script
        self.sequence = sequence
        self.address_info = address_info

    def create_tx_input(self, hash_for_signature, flags):
        public_key = PublicKey.from_hex(self.address_info['public_key_hex'])
        public_key_metadata = self.spv.wallet.get_temp('public_key', public_key)
        if public_key_metadata is None:
            raise Exception("signature error: can't sign without private key to address {}".format(public_key.as_address(self.spv.coin)))
        private_key = public_key_metadata['private_key']
        signature = private_key.sign(hash_for_signature)
        script = Script()
        script.push_bytes(signature + bytes([flags]))
        script.push_bytes(public_key.pubkey)
        return TransactionInput(prevout=self.prevout, script=script)

    def estimated_script_size(self):
        # signatures are at most 73 bytes
        # plus 1 byte for the signature hash type
        # pubkeys are 33 if compressed, 65 if uncompressed
        return 73 + 1 + (len(self.address_info['public_key_hex']) // 2)

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
        return self.get_confirmations() >= self.coin.TRANSACTION_CONFIRMATION_DEPTH

    def get_confirmations(self, spv):
        return spv.txdb.get_tx_depth(self.prevout.tx_hash)
        
    def create_input_creators(self, spv):
        pksic = PubKeySpendInputCreator(spv, self.prevout, self.script, 0xffffffff, self.address_info)
        return [pksic]

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

    def __str__(self):
        return '<PubKeySpend {} BTC prevout={}>'.format(self.coin.format_money(self.amount), str(self.prevout))

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
            'public_key_hex': public_key.as_hex(),
        }

        wallet.add_temp('public_key', public_key, {'private_key': private_key})

        if self.spv.logging_level <= DEBUG:
            print('[PUBKEYPAYMENTS] watching for payments to {}'.format(address))

        public_key = private_key.get_public_key(True)
        address = public_key.as_address(self.spv.coin)

        self.pubkey_addresses[address] = {
            'address'       : address,
            'public_key_hex': public_key.as_hex(),
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
            raise Exception("TODO")

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

