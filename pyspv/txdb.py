import os
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
        self.transaction_cache = {}

        self.blockchain_height = self.spv.blockchain.best_chain['height']

        if self.spv.args.resync:
            try:
                os.unlink(self.transaction_database_file)
            except FileNotFoundError:
                pass
            except:
                print('Error: cannot remove txdb file for resync')
                raise

        with closing(shelve.open(self.transaction_database_file)) as txdb:
            for tx_hash_str in list(txdb.keys()):
                if tx_hash_str.startswith('tx-'):
                    if self.spv.args.resync:
                        txdb.pop(tx_hash_str)
                    else:
                        self.transaction_cache[hexstring_to_bytes(tx_hash_str[3:])] = {
                            'in_blocks': txdb[tx_hash_str]['in_blocks'],
                        }

            if 'watched_block_height' not in txdb or self.spv.args.resync:
                txdb['watched_block_height'] = {}

            self.watched_block_height = txdb['watched_block_height']

    def has_tx(self, tx_hash):
        with self.db_lock: # TODO - maybe this lock isn't needed
            return tx_hash in self.transaction_cache

    def get_tx(self, tx_hash):
        with self.db_lock:
            if tx_hash not in self.transaction_cache:
                return None
            with closing(shelve.open(self.transaction_database_file)) as txdb:
                tx_hash_str = 'tx-' + bytes_to_hexstring(tx_hash)
                return Transaction.unserialize(txdb[tx_hash_str])[0]

    def save_tx(self, tx):
        with self.db_lock:
            tx_hash = tx.hash()
            if tx_hash not in self.transaction_cache:
                with closing(shelve.open(self.transaction_database_file)) as txdb:
                    tx_hash_str = 'tx-' + bytes_to_hexstring(tx_hash)
                    txdb[tx_hash_str] = {
                        'data'     : tx.serialize(),
                        'in_blocks': set(),
                    }
                    self.transaction_cache[tx_hash] = {
                        'in_blocks': set(),
                    }

    def bind_tx(self, tx_hash, block_hash):
        '''associate a block with a transaction; i.e., tx was found in this block. bind_tx needs to be called on each relevent transaction
        before any calls to on_block_added'''
        with self.db_lock:
            if tx_hash not in self.transaction_cache:
                return

            self.transaction_cache[tx_hash]['in_blocks'].add(block_hash)

            tx_hash_str = 'tx-' + bytes_to_hexstring(tx_hash)
            with closing(shelve.open(self.transaction_database_file)) as txdb:
                tx_dict = txdb[tx_hash_str]
                tx_dict['in_blocks'].add(block_hash)
                txdb[tx_hash_str] = tx_dict

                if block_hash not in self.watched_block_height:
                    self.watched_block_height[block_hash] = 0
                    txdb['watched_block_height'] = self.watched_block_height

                if self.spv.logging_level <= DEBUG:
                    print('[TXDB] bound tx {} to block {}'.format(tx_hash_str[3:], bytes_to_hexstring(block_hash)))

    def on_block_removed(self, block_hash):
        with self.db_lock:
            self.blockchain_height -= 1
            if block_hash in self.watched_block_height:
                self.watched_block_height[block_hash] = 0
                with closing(shelve.open(self.transaction_database_file)) as txdb:
                    txdb['watched_block_height'] = self.watched_block_height

    def on_block_added(self, block_hash):
        with self.db_lock:
            self.blockchain_height += 1
            if block_hash in self.watched_block_height:
                self.watched_block_height[block_hash] = self.blockchain_height
                with closing(shelve.open(self.transaction_database_file)) as txdb:
                    txdb['watched_block_height'] = self.watched_block_height
                if self.spv.logging_level <= DEBUG:
                    print('[TXDB] block {} watched in txdb at height={}'.format(bytes_to_hexstring(block_hash), self.blockchain_height))

    def get_tx_depth(self, tx_hash):
        with self.db_lock:
            for block_hash in self.transaction_cache[tx_hash]['in_blocks']:
                h = self.watched_block_height[block_hash]
                if h != 0:
                    return self.blockchain_height - h + 1
            return 0 

