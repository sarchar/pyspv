import shelve
import threading

from contextlib import closing

from .transaction import Transaction
from .util import *

class TransactionDatabase:
    def __init__(self, spv=None):
        self.spv = spv
        self.transaction_database_file = self.spv.config.get_file("txdb")
        self.db_lock = threading.Lock()
        self.transaction_cache = set()

        with closing(shelve.open(self.transaction_database_file)) as txdb:
            for tx_hash_str in txdb.keys():
                self.transaction_cache.add(hexstring_to_bytes(tx_hash_str))

    def has_tx(self, tx_hash):
        with self.db_lock:
            return tx_hash in self.transaction_cache

    def get_tx(self, tx_hash):
        with self.db_lock:
            with closing(shelve.open(self.transaction_database_file)) as txdb:
                if tx_hash not in txdb:
                    return None
                return Transaction.unserialize(txdb[tx_hash])[0]

    def save_tx(self, tx):
        with self.db_lock:
            if tx_hash_str not in self.transaction_cache:
                with closing(shelve.open(self.transaction_database_file)) as txdb:
                    tx_hash = tx.hash()
                    tx_hash_str = bytes_to_hexstring(tx_hash)
                    txdb[tx_hash_str] = tx.serialize()
                    self.transaction_cache.add(tx_hash)

