import shelve
import threading
import time

from contextlib import closing

from .keys import PrivateKey
from .util import *

class Wallet:
    '''The Wallet is responsible for managing private keys and spendable inputs'''
    def __init__(self, spv=None):
        self.spv = spv
        self.payment_types = set()
        self.payment_types_by_name = {}
        self.wallet_file = self.spv.config.get_file("wallet")
        self.wallet_lock = threading.Lock()
        self.spends = []

        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                if 'creation_time' not in d:
                    d['creation_time'] = time.time()

                if not 'spends' in d:
                    d['spends'] = []
                elif isinstance(d['spends'], dict):
                    d['spends'] = []

                if not 'keys' in d:
                    d['keys'] = []

                self.creation_time = d['creation_time']

    def create_new_private_key(self, label=''):
        pk = PrivateKey.create_new()
        self.save_private_key(pk, label=label)
        return pk

    def save_private_key(self, private_key, label=''):
        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                keys = d['keys']
                key_index = len(keys)

                keys.append({
                    'key'   : private_key.serialize(),
                    'label' : label,
                })

                d['keys'] = keys

        for pm in self.payment_types:
            pm.add_key(private_key, key_index)

    def add_spend(self, pm, new_spend):
        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                spends = d['spends']
                spends.append({
                    'spends'       : new_spend.serialize(),
                    'payment_type': pm.__class__.name,
                })

                d['spends'] = spends

                self.spends.append({
                    'spends'       : new_spend,
                    'payment_type': pm,
                })

                self.balance += new_spend.amount

    def load_wallet(self):
        self.balance = 0

        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                if 'spends' in d:
                    for spends in d['spends']:
                        pm = self.payment_types_by_name[spends['payment_type']]
                        self.spends.append(pm.__class__.spend_class.unserialize(spends['spends'])[0])
                        self.balance += self.spends[-1].amount

        if self.spv.logging_level <= INFO:
            print('[WALLET] loaded with balance of {} BTC'.format(self.balance))

    def register_payments(self, pm):
        self.payment_types.add(pm)
        self.payment_types_by_name[pm.__class__.name] = pm

    def private_keys(self):
        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                if 'keys' in d:
                    for e in d['keys']:
                        pk, _ = PrivateKey.unserialize(e['key'])
                        yield pk, e['label']

    def on_tx(self, tx):
        for pm in self.payment_types:
            pm.on_tx(tx)

class Spend:
    def __init__(self, amount):
        self.amount = amount

