from .. import base58

from .basemonitor import BaseMonitor

from ..script import *
from ..transaction import TransactionOutput
from ..util import *
from ..wallet import InvalidAddress

class ScriptHashPayment:
    def __init__(self, address, amount):
        assert isinstance(amount, int), "amount must be in satoshis"
        assert isinstance(address, str), "address must be a string"

        self.address = address
        self.amount = amount
        
    def create_outputs(self, spv):
        address_bytes = int.to_bytes(base58.decode(self.address), spv.coin.ADDRESS_BYTE_LENGTH, 'big')
        k = len(spv.coin.P2SH_ADDRESS_VERSION_BYTES)
        if address_bytes[:k] != spv.coin.P2SH_ADDRESS_VERSION_BYTES:
            raise InvalidAddress("Address version is incorrect")

        address_hash = spv.coin.hash(address_bytes[:-4])
        if address_hash[:4] != address_bytes[-4:]:
            raise InvalidAddress("Address checksum is incorrect")

        script = Script()
        script.push_op(OP_HASH160)
        script.push_bytes(address_bytes[k:-4])
        script.push_op(OP_EQUAL)

        yield TransactionOutput(amount=self.amount, script=script)

class ScriptHashPaymentMonitor(BaseMonitor):
    spend_classes = []

    def __init__(self, spv):
        BaseMonitor.__init__(self, spv)

    def on_spend(self, wallet, spend):
        # TODO
        pass

    def on_redemption_script(self, wallet, redemption_script, metadata):
        address = base58_check(self.spv.coin, self.spv.coin.hash160(redemption_script), version_bytes=self.spv.coin.P2SH_ADDRESS_VERSION_BYTES)
        print('[SCRIPTHASHPAYMENTS] watching for script-hash payment to {}'.format(address))

