import shelve
import threading

from .keys import PrivateKey
from .util import *

class Wallet:
    '''The Wallet is responsible for managing private keys and spendable inputs'''
    def __init__(self, spv=None):
        self.spv = spv
        self.payment_types = set()
        self.wallet_file = self.spv.config.get_file("wallet")
        self.wallet_lock = threading.Lock()
        self.load_wallet()

    def create_new_private_key(self, label=''):
        pk = PrivateKey.create_new()
        self.save_private_key(pk, label=label)
        return pk

    def save_private_key(self, private_key, label=''):
        with self.wallet_lock:
            d = shelve.open(self.wallet_file)

            if not 'keys' in d:
                d['keys'] = []

            keys = d['keys']

            keys.append({
                'key'   : private_key.serialize(),
                'label' : label,
            })

            d['keys'] = keys

        for pm in self.payment_types:
            pm.add_key(private_key)

    def load_wallet(self):
        pass

    def register_payments(self, pm):
        self.payment_types.add(pm)

    def private_keys(self):
        with self.wallet_lock:
            d = shelve.open(self.wallet_file)
            if 'keys' in d:
                for e in d['keys']:
                    pk, _ = PrivateKey.unserialize(e['key'])
                    yield pk, e['label']

