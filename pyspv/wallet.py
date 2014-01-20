import shelve
import threading

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
        self.coins = []

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
            key_index = len(keys)

            keys.append({
                'key'   : private_key.serialize(),
                'label' : label,
            })

            d['keys'] = keys

        for pm in self.payment_types:
            pm.add_key(private_key, key_index)

    def add_coins(self, pm, new_coins):
        with self.wallet_lock:
            d = shelve.open(self.wallet_file)

            if not 'coins' in d:
                d['coins'] = []
            elif isinstance(d['coins'], dict):
                d['coins'] = []

            coins = d['coins']
            coins.append({
                'coins'       : new_coins.serialize(),
                'payment_type': pm.__class__.name,
            })

            d['coins'] = coins

            self.coins.append({
                'coins'       : new_coins,
                'payment_type': pm,
            })

            self.balance += new_coins.amount

    def load_wallet(self):
        self.balance = 0

        with self.wallet_lock:
            d = shelve.open(self.wallet_file)

            if 'coins' in d:
                for coins in d['coins']:
                    pm = self.payment_types_by_name[coins['payment_type']]
                    self.coins.append(pm.__class__.coins.unserialize(coins['coins'])[0])
                    self.balance += self.coins[-1].amount

        if self.spv.logging_level <= INFO:
            print('[WALLET] loaded with balance of {} BTC'.format(self.balance))

    def register_payments(self, pm):
        self.payment_types.add(pm)
        self.payment_types_by_name[pm.__class__.name] = pm

    def private_keys(self):
        with self.wallet_lock:
            d = shelve.open(self.wallet_file)
            if 'keys' in d:
                for e in d['keys']:
                    pk, _ = PrivateKey.unserialize(e['key'])
                    yield pk, e['label']

    def on_tx(self, tx):
        for pm in self.payment_types:
            pm.on_tx(tx)

class Coins:
    def __init__(self, amount):
        self.amount = amount

