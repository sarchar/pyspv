import hashlib

from ..keys import PublicKey, PrivateKey
from ..transaction import TransactionOutput
from ..wallet import InvalidAddress

from ..script import *
from ..util import *

class StealthAddressPayment:
    def __init__(self, address, amount):
        assert isinstance(amount, int), "amount must be in satoshis"
        assert isinstance(address, str), "address must be a string"

        self.address = address
        self.amount = amount
        
    def create_outputs(self, spv):
        address_bytes = int.to_bytes(base58.decode(self.address), spv.coin.STEALTH_ADDRESS_BYTE_LENGTH, 'big')
        k = len(spv.coin.STEALTH_ADDRESS_VERSION_BYTES)
        if address_bytes[:k] != spv.coin.STEALTH_ADDRESS_VERSION_BYTES:
            raise InvalidAddress("Address version is incorrect")

        address_hash = spv.coin.hash(address_bytes[:-4])
        if address_hash[:4] != address_bytes[-4:]:
            raise InvalidAddress("Address checksum is incorrect")

        k = len(spv.coin.STEALTH_ADDRESS_SUFFIX_BYTES)
        if address_bytes[-k-4:-4] != spv.coin.STEALTH_ADDRESS_SUFFIX_BYTES:
            raise InvalidAddress("Address suffix is incorrect")

        public_key = PublicKey(address_bytes[len(spv.coin.STEALTH_ADDRESS_VERSION_BYTES):][:33])

        if spv.logging_level <= DEBUG:
            print("[STEALTHADDRESSPAYMENT] Input Payment Address =", public_key.as_address(spv.coin))

        # Create the ephemeral key used to create the shared secret
        ekey = PrivateKey.create_new()
        epubkey = ekey.get_public_key(True)
        shared_secret_pubkey = public_key.multiply(ekey.as_int())

        if spv.logging_level <= DEBUG:
            print("[STEALTHADDRESSPAYMENT] Shared secret =", bytes_to_hexstring(epubkey.pubkey, reverse=False))
 
        # Yield the shared secret output
        script = Script()
        script.push_op(OP_RETURN)
        script.push_bytes(epubkey.pubkey)
        yield TransactionOutput(amount=0, script=script)

        # Create the actual payment address
        hasher = hashlib.sha256()
        hasher.update(shared_secret_pubkey.pubkey)
        shared_secret = hasher.digest()

        # We need to add shared_secret to Bob's public key
        new_public_key = public_key.add_constant(int.from_bytes(shared_secret, 'big'))
        if spv.logging_level <= DEBUG:
            print("[STEALTHADDRESSPAYMENT] New Payment Address =", new_public_key.as_address(spv.coin))
  
        script = Script()
        script.push_op(OP_DUP)
        script.push_op(OP_HASH160)
        script.push_bytes(new_public_key.as_hash160(spv.coin))
        script.push_op(OP_EQUALVERIFY)
        script.push_op(OP_CHECKSIG)
        yield TransactionOutput(amount=self.amount, script=script)

