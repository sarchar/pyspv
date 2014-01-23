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

    def has_tx(self, tx_hash):
        with self.db_lock:
            with closing(shelve.open(self.transaction_database_file)) as txdb:
                return bytes_to_hexstring(tx_hash) in txdb

    def get_tx(self, tx_hash):
        with self.db_lock:
            with closing(shelve.open(self.transaction_database_file)) as txdb:
                if tx_hash not in txdb:
                    return None
                return Transaction.unserialize(txdb[tx_hash])[0]

    def save_tx(self, tx):
        with self.db_lock:
            with closing(shelve.open(self.transaction_database_file)) as txdb:
                txdb[bytes_to_hexstring(tx.hash())] = tx.serialize()


