from collections import defaultdict
import random
import shelve
import threading
import time

from contextlib import closing

from .keys import PrivateKey
from .util import *

class InvalidAddress(Exception):
    pass

class DuplicateWalletItem(Exception):
    pass

class Wallet:
    '''The Wallet is responsible for managing private keys and spendable inputs'''
    def __init__(self, spv, monitors=None):
        self.spv = spv
        self.payment_types = set()
        self.payment_types_by_name = {}
        self.wallet_file = self.spv.config.get_file("wallet")
        self.wallet_lock = threading.Lock()
        self.tx_lock = threading.Lock()
        self.temp_collections_lock = threading.Lock()
        self.monitors = [m(spv) for m in ([] if monitors is None else monitors)]
        self.spend_classes = {}
        self.collection_sizes = {}
        self.temp_collections = {}
        self.temp_collection_sizes = {}

        for m in monitors:
            for sc in m.spend_classes:
                self.spend_classes[sc.__name__] = sc

    def load(self):
        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                if 'creation_time' not in d:
                    d['creation_time'] = time.time()

                if 'spends' not in d or isinstance(d['spends'], list) or self.spv.args.resync:
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
                    if hasattr(m, 'on_new_' + collection_name):
                        getattr(m, 'on_new_' + collection_name)(item, metadata)

        self.spends = {}
        self.spends_by_index = []
        self.balance = defaultdict(int)
        self.balance_spends = set()
        for _, spend_dict in d['spends'].items():
            spend_class = self.spend_classes[spend_dict['class']]
            spend, _ = spend_class.unserialize(spend_dict['data'], self.spv.coin)
            spend_hash = spend.hash()
            self.spends[spend.hash()] = {
                'spend'   : spend,
            }
            self.spends_by_index.append(spend_hash)
            if not spend.is_spent(self.spv):
                self.balance[spend.category] += spend.amount
                self.balance_spends.add(spend_hash)
            for m in self.monitors:
                if hasattr(m, 'on_new_spend'):
                    getattr(m, 'on_new_spend')(spend)

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
                if hasattr(m, 'on_new_' + collection_name):
                    getattr(m, 'on_new_' + collection_name)(item, metadata)

    def update(self, collection_name, item, metadata):
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

                if item not in collection:
                    raise AttributeError("item {} not in collection {}".format(str(item), collection_name))

                # TODO maybe this is going to get slow with large wallets.
                collection[item] = metadata
                wallet[collection_name] = collection
                d['wallet'] = wallet

            for m in self.monitors:
                if hasattr(m, 'on_' + collection_name):
                    getattr(m, 'on_' + collection_name)(self, item, metadata)

    def get(self, collection_name, item):
        '''item must be implement __hash__ and __eq__. Returns metadata bound to the item or None if not found'''
        assert isinstance(collection_name, str)
        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                wallet = d['wallet']
                if collection_name not in wallet:
                    return None
                return wallet[collection_name][item]

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

            self.temp_collections[collection_name] = collection
            self.temp_collection_sizes[collection_name] += 1

    def get_temp(self, collection_name, item):
        '''item must be implement __hash__ and __eq__. Returns metadata bound to the item or None if not found'''
        assert isinstance(collection_name, str)
        with self.temp_collections_lock:
            collection = self.temp_collections.get(collection_name, {})

            if item not in collection:
                return None

            return collection[item]

    def add_spend(self, spend):
        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                spend_hash = spend.hash()

                spends = d['spends']
                spends[spend_hash] = {
                    'class'   : spend.__class__.__name__,
                    'data'    : spend.serialize(),
                }

                d['spends'] = spends

                self.spends[spend_hash] = {
                    'spend'   : spend,
                }

                self.spends_by_index.append(spend_hash)

                if spend.category not in self.balance:
                    self.balance[spend.category] = 0

                if spend.is_spent(self.spv) and spend_hash in self.balance_spends:
                    self.balance[spend.category] -= spend.amount
                    self.balance_spends.remove(spend_hash)

                if not spend.is_spent(self.spv) and spend_hash not in self.balance_spends:
                    self.balance[spend.category] += spend.amount
                    self.balance_spends.add(spend_hash)

                for m in self.monitors:
                    if hasattr(m, 'on_new_spend'):
                        getattr(m, 'on_new_spend')(spend)

                if self.spv.logging_level <= INFO:
                    print('[WALLET] added {} to wallet category {} (new balance={})'.format(spend.amount, spend.category, self.balance[spend.category]))

                return True

    def update_spend(self, spend):
        with self.wallet_lock:
            with closing(shelve.open(self.wallet_file)) as d:
                spend_hash = spend.hash()

                spends = d['spends']
                if spend_hash not in spends:
                    raise AttributeError("spend does not exist")

                spends.pop(spend_hash)
                spends[spend_hash] = {
                    'class'   : spend.__class__.__name__,
                    'data'    : spend.serialize(),
                }

                d['spends'] = spends

                old_spend = self.spends.pop(spend_hash)
                self.spends[spend_hash] = {
                    'spend'   : spend,
                }

                if spend.category not in self.balance:
                    self.balance[spend.category] = 0

                if spend.is_spent(self.spv) and spend_hash in self.balance_spends:
                    self.balance[spend.category] -= old_spend['spend'].amount
                    self.balance_spends.remove(spend_hash)

                if not spend.is_spent(self.spv) and spend_hash not in self.balance_spends:
                    self.balance[spend.category] += spend.amount
                    self.balance_spends.add(spend_hash)

                if self.spv.logging_level <= INFO:
                    print('[WALLET] updated {} in wallet category {} (new balance={})'.format(spend.amount, spend.category, self.balance[spend.category]))

                return True


    def select_spends(self, categories, amount, dont_select=None):
        if dont_select is None:
            dont_select = set()

        with self.wallet_lock:
            coins_ret = []

            if self.spv.logging_level <= DEBUG:
                print("[WALLET] select_spends: start for {} (categories={})".format(self.spv.coin.format_money(amount), ', '.join(categories)))

            # build a list of spends where all spends are leq than the target
            # and keep track of the spellest spend over the target
            spend_smallest_over_amount = None
            spends_below = []

            # use a random coprime generator to iterate over spends
            # instead of creating a copy of the wallet's unspent outputs
            p = random_coprime(len(self.spends_by_index))

            for i in range(len(self.spends_by_index)):
                spend_hash = self.spends_by_index[(i * p) % len(self.spends_by_index)]
                spend_dict = self.spends[spend_hash]

                spend = spend_dict['spend']

                if spend.hash() in dont_select:
                    continue

                if not spend.is_spendable(self.spv):
                    continue
                
                # Only allow inputs from approved wallet categories
                if spend.category not in categories:
                    continue

                if spend.amount == amount:
                    if self.spv.logging_level <= DEBUG:
                        print("[WALLET] select_spends: found perfect match")
                    return [spend]
                elif spend.amount < (amount + self.spv.coin.DUST_LIMIT):
                    if self.spv.logging_level <= DEBUG:
                        print("[WALLET] select_spends: selecting {}".format(self.spv.coin.format_money(spend.amount)))
                    spends_below.append(spend)
                elif spend_smallest_over_amount is None or spend.amount < spend_smallest_over_amount.amount:
                    spend_smallest_over_amount = spend

            if self.spv.logging_level <= DEBUG and spend_smallest_over_amount is not None:
                print("[WALLET] select_spends: smallest over target is {}".format(self.spv.coin.format_money(spend_smallest_over_amount.amount)))
                    
            total_below = sum(spend.amount for spend in spends_below)
            if total_below == amount:
                if self.spv.logging_level <= DEBUG:
                    print("[WALLET] select_spends: sum of spends_below was a perfect match")
                return spends_below

            if total_below < amount:
                if spend_smallest_over_amount is None:
                    if self.spv.logging_level <= WARNING:
                        print("[WALLET] select_spends: couldn't find enough inputs (total_below is {})".format(total_below))
                    return []
                else:
                    if self.spv.logging_level <= DEBUG:
                        print("[WALLET] select_spends: spends_below don't supply enough value... using a single spend of {} instead".format(self.spv.coin.format_money(spend_smallest_over_amount.amount)))
                    return [spend_smallest_over_amount]

            # this can be slow if there are lots of dusty inputs
            spends_below.sort(key=lambda spend: spend.amount)

            # solve subset sum by stochastic approximation
            best_spends = self.approximate_best_subset(spends_below, amount, 1000)
            best_total = sum(spend.amount for spend in best_spends)
            if best_total != amount and total_below >= amount + self.spv.coin.DUST_LIMIT:
                best_spends = self.approximate_best_subset(spends_below, amount + self.spv.coin.DUST_LIMIT, 1000)
                best_total = sum(spend.amount for spend in best_spends)
                
            # if we have a bigger coin and either the stochastic approximation didn't find a good solution,
            # or the next bigger coin is closer, return the bigger coin
            if spend_smallest_over_amount is not None and ((best_total != amount and best_total < (amount + self.spv.coin.DUST_LIMIT)) or (spend_smallest_over_amount.amount <= best_total)):
                coins_ret.append(spend_smallest_over_amount)
                if self.spv.logging_level <= DEBUG:
                    print("[WALLET] stochastic approximation failed to find a good subset (best was {}).. using a single larger input of {}!".format(best_total, spend_smallest_over_amount.amount))
                return [spend_smallest_over_amount]
            else:
                if self.spv.logging_level <= DEBUG:
                    print("[WALLET] stochastic approximation returned these coins:")
                    for spend in best_spends:
                        print("[WALLET]     spend = {}".format(str(spend)))
                    print("[WALLET] total combined value = {} from {} coins".format(best_total, len(best_spends)))

                return best_spends

    def approximate_best_subset(self, spends, amount, iterations):
        '''returns a list of coins that are cloest to the target amount'''
        if self.spv.logging_level <= DEBUG:
            print("[WALLET] approximate_best_subset: start for {} ({} iterations)".format(self.spv.coin.format_money(amount), iterations))

        # initially start with all spends used
        best_spends = [True] * len(spends)
        best_value = sum(spend.amount for spend in spends)

        for _ in range(iterations):
            if best_value == amount:
                break

            included = [False] * len(spends)
            total = 0

            reached_target = False
            for k in range(2):
                if reached_target:
                    break

                for i in range(len(spends)): 
                    if k == 0:
                        include_this = bool(random.getrandbits(1))
                    else:
                        include_this = not included[i]

                    if not include_this:
                        continue

                    total += spends[i].amount
                    included[i] = True

                    if total < amount:
                        continue

                    reached_target = True
                    if total < best_value:
                        best_value = total
                        best_spends = included.copy()

                    total -= spends[i].amount
                    included[i] = False

        result = []
        for i, include in enumerate(best_spends):
            if include:
                result.append(spends[i])

        return result

    def on_block(self, block):
        with self.tx_lock:
            for m in self.monitors:
                if hasattr(m, 'on_block'):
                    getattr(m, 'on_block')(block)

    def on_tx(self, tx):
        with self.tx_lock:
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

