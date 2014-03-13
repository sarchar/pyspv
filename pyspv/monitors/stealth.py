import hashlib
import struct

from .basemonitor import BaseMonitor
from .pubkey import PubKeySpend
from .. import base58
from ..keys import PrivateKey, PublicKey
from ..serialize import Serialize
from ..transaction import TransactionPrevOut, TransactionOutput, TransactionInput
from ..transactionbuilder import TransactionBuilder
from ..wallet import InvalidAddress, Spend, DuplicateWalletItem

from ..script import *
from ..util import *

class StealthAddressSpendInputCreator:
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
        private_key, _ = PrivateKey.unserialize(self.address_info['private_key'])
        signature = private_key.sign(hash_for_signature)
        script = Script()
        script.push_bytes(signature + bytes([flags]))
        script.push_bytes(private_key.get_public_key(True).pubkey)
        return TransactionInput(prevout=self.prevout, script=script)

    def estimated_script_size(self):
        # signatures are at most 73 bytes
        # plus 1 byte for the signature hash type
        # pubkeys for stealth addresses are always compressed (+1 for size)
        return 2 + 73 + 1 + 1 + 33

# Ths stealth spend is exactly identical to the pubkey spend with the exception
# that it uses a different private key to sign.
class StealthAddressSpend(PubKeySpend):
    def create_input_creators(self, spv, hash_flags):
        sasic = StealthAddressSpendInputCreator(spv, self.prevout, self.script, 0xffffffff, self.address_info, hash_flags)
        return [sasic]

class StealthAddressPaymentMonitor(BaseMonitor):
    spend_classes = [StealthAddressSpend]

    def __init__(self, spv):
        BaseMonitor.__init__(self, spv)
        self.stealth_keys = {}
        self.spend_by_prevout = {}

    def on_new_spend(self, spend):
        # We only care about StealthAddressSpend
        if not isinstance(spend, StealthAddressSpend):
            return

        # Save spend to check if it gets spent
        self.spend_by_prevout[spend.prevout] = spend

    def on_new_private_key(self, private_key, metadata):
        if metadata.get('stealth_payments', False):
            self.stealth_keys[private_key] = metadata

            if self.spv.logging_level <= DEBUG:
                print('[STEALTHADDRESSPAYMENTMONITOR] watching for stealth payments to {}'.format(private_key.get_public_key(True).as_address(self.spv.coin)))

    def on_tx(self, tx):
        #return # TODO right now OpenSSL breaks on 64-bit MT
        tx_hash = tx.hash()

        # check inputs, they might spend coins from the wallet
        # for stealth addresses, we can't know they're getting spend before we've received payment
        for i, input in enumerate(tx.inputs):
            spend = self.spend_by_prevout.get(input.prevout, None)
            if spend is None:
                continue

            # Have we've seen this spend before?
            if tx_hash in spend.spent_in:
                continue

            # Update this Spend with a new spend tx
            spend.spent_in.add(tx_hash)
            self.spv.wallet.update_spend(spend)

            if self.spv.logging_level <= INFO:
                print('[STEALTHADDRESSPAYMENTMONITOR] tx {} spends {} amount={}'.format(bytes_to_hexstring(tx_hash), input.prevout, self.spv.coin.format_money(spend.amount)))

        # First, build a list of OP_RETURN outputs that fit a stealth payment profile
        # And turn those parameters into a set of stealth addresses
        stealth_payment_addresses = {}
        for i, output in enumerate(tx.outputs):
            script = output.script.program
            if len(script) == 35 and script[0] == OP_RETURN and script[1] == 33 and script[2] in (0x02, 0x03):
                epubkey = PublicKey(script[2:])
                for stealth_key in self.stealth_keys:
                    shared_secret_public_key = epubkey.multiply(stealth_key.as_int())
                    hasher = hashlib.sha256()
                    hasher.update(shared_secret_public_key.pubkey)
                    shared_secret = hasher.digest()

                    payment_key = stealth_key.add_constant(int.from_bytes(shared_secret, 'big'))
                    stealth_payment_addresses[payment_key.get_public_key(True).as_hash160(self.spv.coin)] = {
                        'stealth_key': stealth_key,
                        'private_key': payment_key,
                    }


        if list(stealth_payment_addresses) == 0:
            return

        for i, output in enumerate(tx.outputs):
            # Analyze the script for standard pubkey payments to one of our stealth addresses
            script = output.script.program
            if len(script) == 25 and script[0] == OP_DUP \
                         and script[1] == OP_HASH160 and script[2] == 20 \
                         and script[23] == OP_EQUALVERIFY and script[24] == OP_CHECKSIG:
                # Pay-to-pubkey-hash
                address_bytes = script[3:23]
            else:
                # Not a pubkey payment
                continue

            # Is this an address we care about?
            address_info = stealth_payment_addresses.get(address_bytes, None)
            if address_info is None:
                continue

            # Yes, first save this private key
            stealth_key = self.stealth_keys[address_info['stealth_key']]
            try:
                self.spv.wallet.add('stealth_private_keys', address_info['private_key'], {'label': stealth_key['label']})
            except DuplicateWalletItem:
                # This is fine.
                pass

            # make sure we save this tx
            self.spv.txdb.save_tx(tx)

            # Build a stealth spend
            address = address_info['private_key'].get_public_key(True).as_address(self.spv.coin)
            prevout = TransactionPrevOut(tx_hash, i)
            spend = StealthAddressSpend(self.spv.coin, 'default', output.amount, address, prevout, script, {'private_key': address_info['private_key'].serialize()})

            # Add the spend to the wallet
            if not self.spv.wallet.add_spend(spend):
                if self.spv.logging_level <= DEBUG:
                    print('[STEALTHADDRESSPAYMENTMONITOR] payment of {} to {} already seen'.format(output.amount, address))
                continue

            if self.spv.logging_level <= INFO:
                print('[STEALTHADDRESSPAYMENTMONITOR] processed payment of {} to {}'.format(output.amount, address))

