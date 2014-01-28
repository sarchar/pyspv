import shelve
import threading
import time

from contextlib import closing

from .keys import PrivateKey
from .util import *

class DuplicateWalletItem(Exception):
    pass

class Wallet:
    '''The Wallet is responsible for managing private keys and spendable inputs'''
    def __init__(self, spv=None, monitors=[]):
        self.spv = spv
        self.payment_types = set()
        self.payment_types_by_name = {}
        self.wallet_file = self.spv.config.get_file("wallet")
        self.wallet_lock = threading.Lock()
        self.spends = []
        self.monitors = [m(spv) for m in monitors]
        self.collection_sizes = {}

        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                if 'creation_time' not in d:
                    d['creation_time'] = time.time()

                if not 'spends' in d:
                    d['spends'] = []
                elif isinstance(d['spends'], dict):
                    d['spends'] = []

                # TODO - delete this code after saving old keys
                if 'keys' in d:
                    print("!!!!!!!!!! OLD KEYS !!!!!!!!!!!!")
                    for key in d['keys']:
                        print(PrivateKey.unserialize(key['key'])[0].as_wif(self.spv.coin, False))
                        print(PrivateKey.unserialize(key['key'])[0].as_wif(self.spv.coin, True))
                    print("!!!!!!!!!! OLD KEYS !!!!!!!!!!!!")
                        
                if 'wallet' not in d:
                    d['wallet'] = {}

                self.creation_time = d['creation_time']
                self.__load_wallet(d)

    def __load_wallet(self, d):
        collections = d['wallet']
        for collection_name in collections.keys():
            self.collection_sizes[collection_name] = len(collections[collection_name])
            for item, metadata in collections[collection_name].items():
                for m in self.monitors:
                    if hasattr(m, 'on_' + collection_name):
                        getattr(m, 'on_' + collection_name)(item, metadata)

    def add(self, collection_name, item, metadata):
        '''item must be pickle serializable and implement __hash__ and __eq__'''
        assert isinstance(collection_name, str)
        assert isinstance(metadata, dict)

        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                wallet = d['wallet']
                if collection_name not in wallet:
                    collection = {}
                else:
                    collection = wallet[collection_name]

                if item in collection:
                    raise DuplicateWalletItem()

                # TODO maybe this is going to get slow with large wallets.
                collection[item] = metadata
                wallet[collection_name] = collection
                d['wallet'] = wallet

            if collection_name not in self.collection_sizes:
                self.collection_sizes[collection_name] = 0
            self.collection_sizes[collection_name] += 1

            for m in self.monitors:
                if hasattr(m, 'on_' + collection_name):
                    getattr(m, 'on_' + collection_name)(item, metadata)

    def len(self, collection_name):
        with self.wallet_lock:
            return self.collection_sizes.get(collection_name, 0)

    def add_spend(self, pm, new_spend):
        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                spends = d['spends']
                spends.append({
                    'spends'       : new_spend.serialize(),
                    'payment_type': pm.__class__.__name__,
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
        self.payment_types_by_name[pm.__class__.__name__] = pm

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

    def __hash__(self):
        return self.hash()

    def __eq__(self, other):
        return self is other or (self.__class__ is other.__class__ and self.hash() == other.hash())
        
    def hash(self):
        raise self.spv.coin.hash(self.serialize())

    def serialize(self):
        raise NotImplementedError("must implement in derived class")

