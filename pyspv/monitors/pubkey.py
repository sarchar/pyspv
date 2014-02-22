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

class PubKeySpendInputCreator:
    '''Input creators need to define the following class properties:
        self.prevout : a TransactionPrevOut
        self.script  : a byte sequence containing scriptPubKey
        self.sequence: the sequence number of the final TransactionInput
        self.hash_flags: the flags used for hashing and signing

        Everything else can be class-specific, but the above are used for serialization and signing
    '''

    def __init__(self, spv, prevout, script, sequence, address_info, hash_flags):
        self.spv = spv
        self.prevout = prevout
        self.script = script
        self.sequence = sequence
        self.address_info = address_info
        self.hash_flags = hash_flags

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
        # signatures are at most 73 bytes (+2 for size)
        # plus 1 byte for the signature hash type
        # pubkeys are 33 if compressed, 65 if uncompressed (+1 for size)
        return 2 + 73 + 1 + 1 + (len(self.address_info['public_key_hex']) // 2)

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

    def is_spent(self, spv):
        return any(not spv.txdb.is_conflicted(tx_hash) for tx_hash in self.spent_in)

    def is_spendable(self, spv):
        return not self.is_spent(spv) and self.get_confirmations(spv) >= self.coin.TRANSACTION_CONFIRMATION_DEPTH

    def get_confirmations(self, spv):
        return spv.txdb.get_tx_depth(self.prevout.tx_hash)
        
    def create_input_creators(self, spv, hash_flags):
        pksic = PubKeySpendInputCreator(spv, self.prevout, self.script, 0xffffffff, self.address_info, hash_flags)
        return [pksic]

    def serialize(self):
        return Serialize.serialize_string(self.category) + Serialize.serialize_variable_int(self.amount) + \
               self.prevout.serialize() + Serialize.serialize_string(self.address) + \
               struct.pack('<L', len(self.script)) + self.script + \
               Serialize.serialize_dict(self.address_info) + \
               Serialize.serialize_list(list(self.spent_in))

    @classmethod
    def unserialize(cls, data, coin):
        category, data = Serialize.unserialize_string(data)
        amount, data = Serialize.unserialize_variable_int(data)
        prevout, data = TransactionPrevOut.unserialize(data)
        address, data = Serialize.unserialize_string(data)

        script_length = struct.unpack("<L", data[:4])[0]
        script = data[4:4+script_length]

        address_info, data = Serialize.unserialize_dict(data[4+script_length:])

        spent_in, data = Serialize.unserialize_list(data)

        spends = cls(coin, category, amount, address, prevout, script, address_info, spent_in=spent_in)
        return spends, data

    def __str__(self):
        return '<{} {} BTC prevout={} address={}{}>'.format(self.__class__.__name__, self.coin.format_money(self.amount), str(self.prevout), self.address, ' SPENT' if len(self.spent_in) else '')

class PubKeyPaymentMonitor(BaseMonitor):
    spend_classes = [PubKeySpend]

    def __init__(self, spv):
        BaseMonitor.__init__(self, spv)
        self.pubkey_addresses = {}
        self.spend_by_prevout = {}

    def on_new_spend(self, spend):
        # We only care about PubKeySpend
        if not isinstance(spend, PubKeySpend):
            return

        # Save spend to check if it gets spent
        self.spend_by_prevout[spend.prevout] = spend

    def on_new_private_key(self, private_key, metadata):
        for compressed in (False, True):
            public_key = private_key.get_public_key(compressed)
            address = public_key.as_address(self.spv.coin)

            self.pubkey_addresses[address] = {
                'address'       : address,
                'public_key_hex': public_key.as_hex(),
            }

            self.spv.wallet.add_temp('public_key', public_key, {'private_key': private_key})
            self.spv.wallet.add_temp('address', address, {'public_key': public_key})

            if self.spv.logging_level <= DEBUG:
                print('[PUBKEYPAYMENTMONITOR] watching for payments to {}'.format(address))

    def on_tx(self, tx):
        tx_hash = tx.hash()

        # check inputs, they might spend coins from the wallet, even if we don't know about the coins yet
        for i, input in enumerate(tx.inputs):
            spend = self.spend_by_prevout.get(input.prevout, None)
            if spend is not None:
                # Have we've seen this spend before?
                if tx_hash in spend.spent_in:
                    continue

                # Update this Spend with a new spend tx
                spend.spent_in.add(tx_hash)
                self.spv.wallet.update_spend(spend)

                if self.spv.logging_level <= INFO:
                    print('[PUBKEYPAYMENTMONITOR] tx {} spends {} amount={}'.format(bytes_to_hexstring(tx_hash), input.prevout, self.spv.coin.format_money(spend.amount)))

                continue

            # check this input and if it's a pubkey spend (<sig> <pubkey>) check to see if 
            # pubkey is in our wallet. if it is, remember this spend for later.
            if len(input.script.program) < 106:
                continue

            # The first data push must be a signature
            size = input.script.program[0]
            if not (68 <= size <= 73):
                continue

            # The second data push has to be a pubkey, though in the future we may need to extract the public key from the signature
            size2 = input.script.program[size+1]
            if size2 not in (33, 65):
                continue

            public_key_bytes = input.script.program[size+2:]
            if len(public_key_bytes) != size2:
                continue

            # Do we care about this public key?
            public_key = PublicKey(public_key_bytes)
            public_key_metadata = self.spv.wallet.get('public_key', public_key)
            if public_key_metadata is None:
                continue

            # TODO verify signature!

            # Yes, be sure to save the tx
            self.spv.txdb.save_tx(tx)

            # Add this spending transaction to the list of spent_in transaction ids for use whenever the payment is received
            unknown_pubkey_spend_key = (input.prevout.tx_hash, input.prevout.n)
            unknown_pubkey_spend_metadata = self.spv.wallet.get('unknown_pubkey_spends', unknown_pubkey_spend_key)
            if unknown_pubkey_spend_metadata is not None:
                unknown_pubkey_spend_metadata['spent_in'].append(tx_hash)
                self.spv.wallet.update('unknown_pubkey_spends', unknown_pubkey_spend_key, unknown_pubkey_spend_metadata)
            else:
                unknown_pubkey_spend_metadata = {'spent_in': [tx_hash]}
                self.spv.wallet.add('unknown_pubkey_spends', unknown_pubkey_spend_key, unknown_pubkey_spend_metadata)

            if self.spv.logging_level <= DEBUG:
                print('[PUBKEYPAYMENTMONITOR] tx {} spends {} from our wallet but we dont know the spend yet!'.format(bytes_to_hexstring(tx_hash), input.prevout))

        for i, output in enumerate(tx.outputs):
            # Analyze the script for standard pubkey payments
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

            # Is this an address we care about?
            address_info = self.pubkey_addresses.get(address, None)
            if address_info is None:
                continue

            # Yes, first make sure it's in the txdb
            self.spv.txdb.save_tx(tx)

            # Build a pubkey spend
            prevout = TransactionPrevOut(tx_hash, i)
            spend = PubKeySpend(self.spv.coin, 'default', output.amount, address, prevout, script, address_info)

            # Since it's possible this spend has been spent, check the wallet for unknown spends and add them
            # to spend.spent_in
            unknown_pubkey_spend_key = (tx_hash, i)
            unknown_pubkey_spend_metadata = self.spv.wallet.get('unknown_pubkey_spends', unknown_pubkey_spend_key)
            if unknown_pubkey_spend_metadata is not None:
                for tx_hash in unknown_pubkey_spend_metadata['spent_in']:
                    spend.spent_in.add(tx_hash)

            # Add to the wallet
            if not self.spv.wallet.add_spend(spend):
                if self.spv.logging_level <= DEBUG:
                    print('[PUBKEYPAYMENTMONITOR] payment of {} to {} already seen'.format(output.amount, address))
                continue

            if self.spv.logging_level <= INFO:
                print('[PUBKEYPAYMENTMONITOR] processed payment of {} to {}'.format(output.amount, address))

