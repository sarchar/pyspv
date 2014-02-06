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

class PubKeyPayment:
    def __init__(self, address, amount):
        assert isinstance(amount, int), "amount must be in satoshis"
        assert isinstance(address, str), "address must be a string"

        self.address = address
        self.amount = amount
        
    def create_outputs(self, spv):
        address_bytes = int.to_bytes(base58.decode(self.address), spv.coin.ADDRESS_BYTE_LENGTH, 'big')
        k = len(spv.coin.ADDRESS_VERSION_BYTES)
        if address_bytes[:k] != spv.coin.ADDRESS_VERSION_BYTES:
            raise InvalidAddress("Address version is incorrect")

        address_hash = spv.coin.hash(address_bytes[:-4])
        if address_hash[:4] != address_bytes[-4:]:
            raise InvalidAddress("Address checksum is incorrect")

        script = Script()
        script.push_op(OP_DUP)
        script.push_op(OP_HASH160)
        script.push_bytes(address_bytes[k:-4])
        script.push_op(OP_EQUALVERIFY)
        script.push_op(OP_CHECKSIG)

        yield TransactionOutput(amount=self.amount, script=script)

class PubKeyChange:
    def __init__(self):
        pass

    def create_one(self, spv):
        change_private_key = PrivateKey.create_new()
        change_address = change_private_key.get_public_key(True).as_hash160(spv.coin)

        script = Script()
        script.push_op(OP_DUP)
        script.push_op(OP_HASH160)
        script.push_bytes(change_address)
        script.push_op(OP_EQUALVERIFY)
        script.push_op(OP_CHECKSIG)

        spv.wallet.add('private_key', change_private_key, {'label': ''})
        return TransactionOutput(amount=0, script=script)

class PubKeySpendInputCreator:
    '''Input creators need to define the following class values:
        self.prevout : a TransactionPrevOut
        self.script  : a byte sequence containing scriptPubKey
        self.sequence: the sequence number of the final TransactionInput

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

    def destination_name(self):
        return self.address

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

        spends = PubKeySpend(coin, category, amount, address, prevout, script, address_info, spent_in=spent_in)
        return spends, data

    def __str__(self):
        return '<PubKeySpend {} BTC prevout={}{}>'.format(self.coin.format_money(self.amount), str(self.prevout), ' SPENT' if len(self.spent_in) else '')

class PubKeyPaymentMonitor(BaseMonitor):
    spend_classes = [PubKeySpend]

    def __init__(self, spv):
        BaseMonitor.__init__(self, spv)
        self.pubkey_addresses = {}
        self.prevouts = {}

    def on_spend(self, wallet, spend):
        if not isinstance(spend, PubKeySpend):
            # We only care about pubkey spends
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
        tx_hash = tx.hash()

        if self.spv.txdb.has_tx(tx_hash):
            # We've seen this tx before.  Done.
            return

        # check inputs, they might spend coins from the wallet
        for i, input in enumerate(tx.inputs):
            spend = self.prevouts.get(input.prevout, None)
            if spend is None:
                # check this input and if it's a pubkey spend (<sig> <pubkey>) check to see if 
                # pubkey is in our wallet. if it is, remember this spend for later.
                if len(input.script.program) < 106:
                    continue

                size = input.script.program[0]
                if size not in (71, 72, 73): # Must be a signature
                    continue

                size2 = input.script.program[size+1] # Must be a pubkey
                if size2 not in (33, 65):
                    continue

                public_key_bytes = input.script.program[size+2:]
                public_key = PublicKey(public_key_bytes)
                public_key_metadata = self.spv.wallet.get('public_key', public_key)
                if public_key_metadata is not None:
                    unknown_spend_key = (input.prevout.tx_hash, input.prevout.n)

                    if self.spv.logging_level <= DEBUG:
                        print('[SPEND] key {} spends from our wallet but we dont know the spend yet!'.format(key))

                    unknown_spend_metadata = self.spv.wallet.get('unknown_spend', unknown_spend_key)
                    if unknown_spend_metadata is not None:
                        unknown_spend_metadata['spent_in'].append(tx_hash)
                        self.spv.wallet.update('unknown_spend', unknown_spend_key, unknown_spend_metadata)
                    else:
                        unknown_spend_metadata = {'spent_in': [tx_hash]}
                        self.spv.wallet.add('unknown_spend', unknown_spend_key, unknown_spend_metadata)

                    if not tx_saved:
                        self.spv.txdb.save_tx(tx)
                        tx_saved = True
                
                continue

            if tx_hash in spend.spent_in:
                # We've seen this spend before
                continue

            # this spend is spent!
            if self.spv.logging_level <= INFO:
                print('[SPEND] tx {} spends {} amount={}'.format(bytes_to_hexstring(tx_hash), input.prevout, self.spv.coin.format_money(spend.amount)))

            spend.spent_in.add(tx_hash)
            self.spv.wallet.update_spend(spend)

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
                prevout = TransactionPrevOut(tx_hash, i)
                spend = PubKeySpend(self.spv.coin, 'default', output.amount, address, prevout, script, address_info)
                if self.spv.wallet.add_spend(spend):
                    unknown_spend_key = (tx_hash, i)
                    unknown_spend_metadata = self.spv.wallet.get('unknown_spend', unknown_spend_key)
                    if unknown_spend_metadata is not None:
                        for tx_hash in unknown_spend_metadata['spent_in']:
                            # this spend is spent already
                            spend.spent_in.add(tx_hash)
                        self.wallet.update_spend(spend)
                        
                    if self.spv.logging_level <= INFO:
                        print('[PUBKEYPAYMENTMONITOR] processed payment of {} to {}'.format(output.amount, address))
                    if not tx_saved:
                        self.spv.txdb.save_tx(tx)
                        tx_saved = True
                else:
                    if self.spv.logging_level <= DEBUG:
                        print('[PUBKEYPAYMENTMONITOR] payment of {} to {} already seen'.format(output.amount, address))

