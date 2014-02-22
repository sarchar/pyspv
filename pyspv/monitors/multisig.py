import struct
from .. import base58

from .basemonitor import BaseMonitor

from ..keys import PrivateKey, PublicKey
from ..script import *
from ..serialize import Serialize
from ..transaction import TransactionInput, TransactionOutput, TransactionPrevOut
from ..util import *
from ..wallet import InvalidAddress, Spend

class MultisigScriptHashSpendInputCreator:
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
        self.sequence = sequence
        self.address_info = address_info
        self.hash_flags = hash_flags

        # P2SH signs the redemption script, not the scriptPubKey
        self.script_p2sh = script
        self.script = hexstring_to_bytes(address_info['redemption_script'], reverse=False)

    def create_tx_input(self, hash_for_signature, flags):
        script = Script()
        script.push_op(OP_0)

        n = 0
        for public_key_bytes in self.address_info['public_keys']:
            if n >= self.address_info['nreq']:
                break
            public_key_metadata = self.spv.wallet.get_temp('public_key', PublicKey(public_key_bytes))
            if public_key_metadata is not None and 'private_key' in public_key_metadata:
                private_key = public_key_metadata['private_key']
                signature = private_key.sign(hash_for_signature)
                script.push_bytes(signature + bytes([flags]))
                n += 1

        if n < self.address_info['nreq']:
            raise Exception("signature error: not enough signatures for Multisignature Spend")

        script.push_bytes(self.script)

        return TransactionInput(prevout=self.prevout, script=script)

    def estimated_script_size(self):
        # signatures are at most 73 bytes, there are nreq of them
        # plus 1 byte for the signature hash type on each sig
        # plus probably 2 bytes for the redemption script size, plus the redemption script iself
        return (73 + 1) * self.address_info['nreq'] + 2 + len(self.script)

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

    def is_spent(self, spv):
        return any(not spv.txdb.is_conflicted(tx_hash) for tx_hash in self.spent_in)

    def is_spendable(self, spv):
        return not self.is_spent(spv) and self.get_confirmations(spv) >= self.coin.TRANSACTION_CONFIRMATION_DEPTH and self.has_signing_keys(spv)

    def has_signing_keys(self, spv):
        n = 0
        for public_key_bytes in self.address_info['public_keys']:
            public_key = PublicKey(public_key_bytes)
            public_key_metadata = spv.wallet.get_temp('public_key', public_key)
            if public_key_metadata is not None and 'private_key' in public_key_metadata:
                n += 1
        return n >= self.address_info['nreq']

    def get_confirmations(self, spv):
        return spv.txdb.get_tx_depth(self.prevout.tx_hash)
        
    def create_input_creators(self, spv, hash_flags):
        pksic = MultisigScriptHashSpendInputCreator(spv, self.prevout, self.script, 0xffffffff, self.address_info, hash_flags)
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
        self.spend_by_prevout = {}
        self.script_addresses = {}

    def on_new_spend(self, spend):
        # We only care about multisig spends
        if not isinstance(spend, MultisigScriptHashSpend):
            return

        # Save spend to check if it gets spent
        self.spend_by_prevout[spend.prevout] = spend

    def on_new_redemption_script(self, redemption_script, metadata):
        # parse redemption_script to verify it's a multisig redemption script
        if len(redemption_script) < 3 or redemption_script[-1] != OP_CHECKMULTISIG:
            return

        if redemption_script[0] == OP_0:
            nreq = 0
        else:
            nreq = redemption_script[0] - OP_1 + 1

        if nreq < 0 or nreq > 9:
            return

        # Get the pubkeys out of the script
        index = 1
        public_keys = []
        while index < len(redemption_script) - 2:
            size = redemption_script[index]
            if size not in (33, 65): # not a public key, too bad
                return
            if len(redemption_script) - (index + 1) < size:
                return
            public_keys.append(redemption_script[index+1:index+1+size])
            if (size == 33 and (public_keys[-1][0] not in (0x02, 0x03))) or (size == 65 and public_keys[-1][0] != 0x04):
                return
            index += size + 1

        if (redemption_script[-2] - OP_1 + 1) != len(public_keys):
            return

        address = base58_check(self.spv.coin, self.spv.coin.hash160(redemption_script), version_bytes=self.spv.coin.P2SH_ADDRESS_VERSION_BYTES)

        # TODO on_public_key could check if any of our redemption_scripts reference that pubkey and if a private key is available for signing, etc

        self.script_addresses[address] = {
            'address'          : address,
            'redemption_script': bytes_to_hexstring(redemption_script, reverse=False),
            'nreq'             : nreq,
            'public_keys'      : public_keys,
        }

        self.spv.wallet.add_temp('address', address, {'redemption_script': redemption_script})

        if self.spv.logging_level <= DEBUG:
            print('[MULTISIGSCRIPTHASHPAYMENTMONITOR] watching for multi-signature payment to {}'.format(address))
            print('[MULTISIGSCRIPTHASHPAYMENTMONITOR] {} of {} public_keys: {}'.format(nreq, len(public_keys), ', '.join(bytes_to_hexstring(public_key, reverse=False) for public_key in public_keys)))

    def on_tx(self, tx):
        tx_hash = tx.hash()

        # check inputs, they might spend coins from the wallet
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
                    print('[MULTISIGSCRIPTHASHPAYMENTMONITOR] tx {} spends {} amount={}'.format(bytes_to_hexstring(tx_hash), input.prevout, self.spv.coin.format_money(spend.amount)))

                continue

            # check this input and if it's a multisig p2sh spend (OP_0 <sig> .. <sig> <redemption_script>) and check to see if 
            # the redemption script is in our wallet. if it is, remember this spend for later.
            if len(input.script.program) == 0 or input.script.program[0] != OP_0:
                continue

            # Break the program into data pushes... TODO: move this to script.py
            index = 1
            pushes = []
            while index < len(input.script.program):
                size = input.script.program[index]
                if size == OP_PUSHDATA1 and (index+1) < len(input.script.program):
                    size = input.script.program[index+1]
                    index += 2
                elif size == OP_PUSHDATA2 and (index+2) < len(input.script.program):
                    size = input.script.program[index+1] | (input.script.program[index+2] << 8)
                    index += 3
                elif size == OP_PUSHDATA4 and (index+4) < len(input.script.program):
                    size = input.script.program[index+1] | (input.script.program[index+2] << 8) | (input.script.program[index+3] << 16) | (input.script.program[index+4] << 24)
                    index += 5
                pushes.append(input.script.program[index:index+size])
                index += size

            # The last data push has to be our redemption script
            if len(pushes) == 0:
                continue

            redemption_script = pushes[-1]
            address = base58_check(self.spv.coin, self.spv.coin.hash160(redemption_script), version_bytes=self.spv.coin.P2SH_ADDRESS_VERSION_BYTES)
            address_info = self.script_addresses.get(address, None)
            if address_info is None:
                continue

            # Yes, be sure to save the tx
            self.spv.txdb.save_tx(tx)

            # Add this spending transaction to the list of spent_in transaction ids for use whenever the payment is received
            unknown_redemption_script_spend_key = (input.prevout.tx_hash, input.prevout.n)
            unknown_redemption_script_spend_metadata = self.spv.wallet.get('unknown_redemption_script_spends', unknown_redemption_script_spend_key)
            if unknown_redemption_script_spend_metadata is not None:
                unknown_redemption_script_spend_metadata['spent_in'].append(tx_hash)
                self.spv.wallet.update('unknown_redemption_script_spends', unknown_redemption_script_spend_key, unknown_redemption_script_spend_metadata)
            else:
                unknown_redemption_script_spend_metadata = {'spent_in': [tx_hash]}
                self.spv.wallet.add('unknown_redemption_script_spends', unknown_redemption_script_spend_key, unknown_redemption_script_spend_metadata)

            if self.spv.logging_level <= DEBUG:
                print('[MULTISIGSCRIPTHASHPAYMENTMONITOR] tx {} spends {} from our wallet but we dont know the spend yet!'.format(bytes_to_hexstring(tx_hash), input.prevout))

        for i, output in enumerate(tx.outputs):
            # Analyze the script for P2SH
            script = output.script.program
            if len(script) == 23 and script[0] == OP_HASH160 and script[1] == 20 and script[-1] == OP_EQUAL:
                redemption_script_hash = script[2:22]
            else:
                continue

            # Check to see if we care about this scripthash
            address = base58_check(self.spv.coin, redemption_script_hash, version_bytes=self.spv.coin.P2SH_ADDRESS_VERSION_BYTES)
            address_info = self.script_addresses.get(address, None)
            if address_info is None:
                continue

            self.spv.txdb.save_tx(tx)

            # Build a multisig payment
            # TODO - distinguish between the ones we can/can't spend
            prevout = TransactionPrevOut(tx_hash, i)
            spend = MultisigScriptHashSpend(self.spv.coin, 'default', output.amount, address, prevout, script, address_info)

            unknown_redemption_script_spend_key = (tx_hash, i)
            unknown_redemption_script_spend_metadata = self.spv.wallet.get('unknown_redemption_script_spend', unknown_redemption_script_spend_key)
            if unknown_redemption_script_spend_metadata is not None:
                # this spend is spent already
                for tx_hash in unknown_redemption_script_spend_metadata['spent_in']:
                    spend.spent_in.add(tx_hash)
 
            if not self.spv.wallet.add_spend(spend):
                if self.spv.logging_level <= DEBUG:
                    print('[MULTISIGSCRIPTHASHPAYMENTMONITOR] payment of {} to {} already seen'.format(output.amount, address))
                continue

                   
            if self.spv.logging_level <= INFO:
                print('[MULTISIGSCRIPTHASHPAYMENTMONITOR] processed payment of {} to {}'.format(output.amount, address))

