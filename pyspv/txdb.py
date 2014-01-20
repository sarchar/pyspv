import shelve
import threading

from .util import *

class TransactionDatabase:
    def __init__(self, spv=None):
        self.spv = spv
        self.transaction_database_file = self.spv.config.get_file("txdb")
        self.db_lock = threading.Lock()

    def has_tx(self, tx_hash):
        with self.db_lock:
            txdb = shelve.open(self.transaction_database_file)
            return bytes_to_hexstring(tx_hash) in txdb

    def save_tx(self, tx):
        with self.db_lock:
            txdb = shelve.open(self.transaction_database_file)
            txdb[bytes_to_hexstring(tx.hash())] = tx.serialize()

