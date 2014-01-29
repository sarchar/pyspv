from collections import defaultdict
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
        self.temp_collections_lock = threading.Lock()
        self.monitors = [m(spv) for m in monitors]
        self.spend_classes = {}
        self.collection_sizes = {}
        self.temp_collections = {}
        self.temp_collection_sizes = {}

        for m in monitors:
            for sc in m.spend_classes:
                self.spend_classes[sc.__name__] = sc

        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                if 'creation_time' not in d:
                    d['creation_time'] = time.time()

                if 'spends' not in d or isinstance(d['spends'], list):
                    d['spends'] = {}

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
                        getattr(m, 'on_' + collection_name)(self, item, metadata)

        self.spends = {}
        self.balance = defaultdict(int)
        for _, spend_dict in d['spends'].items():
            spend_class = self.spend_classes[spend_dict['class']]
            spend, _ = spend_class.unserialize(spend_dict['data'], self.spv.coin)
            self.spends[spend.hash()] = {
                'spend'   : spend,
                'spent'   : False,
            }
            self.balance[spend.category] += spend.amount
            for m in self.monitors:
                if hasattr(m, 'on_spend'):
                    getattr(m, 'on_spend')(self, spend)

        if self.spv.logging_level <= INFO:
            print('[WALLET] loaded with balance of {} BTC'.format(dict(self.balance)))

    def len(self, collection_name):
        with self.wallet_lock:
            return self.collection_sizes.get(collection_name, 0)

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
                    getattr(m, 'on_' + collection_name)(self, item, metadata)

    def add_temp(self, collection_name, item, metadata):
        '''item must be implement __hash__ and __eq__'''
        assert isinstance(collection_name, str)
        assert isinstance(metadata, dict)
        with self.temp_collections_lock:
            collection = self.temp_collections.get(collection_name, {})

            if item in collection:
                raise DuplicateWalletItem()

            collection[item] = metadata

            if collection_name not in self.temp_collection_sizes:
                self.temp_collection_sizes[collection_name] = 0
            self.temp_collection_sizes[collection_name] += 1

    def add_spend(self, spend):
        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                spend_hash = spend.hash()

                spends = d['spends']
                spends[spend_hash] = {
                    'class'   : spend.__class__.__name__,
                    'data'    : spend.serialize(),
                    'spent'   : False,
                }

                d['spends'] = spends

                self.spends[spend_hash] = {
                    'spend'   : spend,
                    'spent'   : False,
                }

                if spend.category not in self.balance:
                    self.balance[spend.category] = 0

                self.balance[spend.category] += spend.amount

                if self.spv.logging_level <= INFO:
                    print('[WALLET] added {} to wallet category {} (new balance={})'.format(spend.amount, spend.category, self.balance[spend.category]))

                return True

    def on_tx(self, tx):
        for m in self.monitors:
            if hasattr(m, 'on_tx'):
                getattr(m, 'on_tx')(tx)

class Spend:
    def __init__(self, coin, category, amount):
        self.coin = coin
        self.category = category
        self.amount = amount

    def __hash__(self):
        return self.hash()

    def __eq__(self, other):
        return self is other or (self.__class__ is other.__class__ and self.hash() == other.hash())
        
    def hash(self):
        return self.coin.hash(self.serialize())

    def serialize(self):
        raise NotImplementedError("must implement in derived class")

