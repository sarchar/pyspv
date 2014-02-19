from ..keys import PrivateKey
from ..transaction import TransactionOutput
from ..wallet import InvalidAddress

from ..script import *
from ..util import *

class MultisigScriptHashPayment:
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

