
from .payments import BasePayments
from ..util import *

class SimplePayments(BasePayments):
    def __init__(self, spv):
        BasePayments.__init__(self, spv)

        self.watch_addresses = {}

        # Loop over all private keys, and build a set of bitcoin addresses
        for i, e in enumerate(self.spv.wallet.private_keys()):
            pk, label = e

            address = pk.get_public_key(False).as_address(self.spv.coin)
            if self.spv.logging_level <= DEBUG:
                print('[SIMPLEPAYMENTS] watching for payments to {}'.format(address))
            self.watch_addresses[address] = {
                'compressed': False,
                'key_index' : i,
            }

            address = pk.get_public_key(True).as_address(self.spv.coin)
            if self.spv.logging_level <= DEBUG:
                print('[SIMPLEPAYMENTS] watching for payments to {}'.format(address))
            self.watch_addresses[address] = {
                'compressed': True,
                'key_index' : i,
            }

    def on_tx(self, tx):
        pass

