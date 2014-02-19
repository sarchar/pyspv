from ..keys import PrivateKey
from ..transaction import TransactionOutput
from ..wallet import InvalidAddress

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


