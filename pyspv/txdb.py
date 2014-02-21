import os
import shelve
import threading

from contextlib import closing

from .transaction import Transaction
from .util import *

class TransactionDatabase:
    '''
    The TransactionDatabase is responsible for remembering transactions and tracking their depth in the blockchain.

    It's primary goal is to confirm to the wallet that outputs are spendable (because they've been confirmed) and to
    discern "conflicted" transactions (by noticing duplicate inputs in orphan transactions/blockchain transactions)

    The strategy to discern conflicted transactions goes like this:

    1. A transaction that we care about watching is added to the transaction database with save_tx
    2. This transaction is considered orphaned immediately, and save_tx takes note of all inputs.
    3. This transaction remains orphaned until it's been bound to one more more blocks with bind_tx
       (note: bind_tx has to be called BEFORE the block is added to the blockchain)
    4. Each of the bound blocks are added to a set of watched block heights
    5. We monitor the growth of the blockchain and once a transaction ends up at a really deep depth such that reorganization is extremely unlikely,
       then scan the inputs in the confirmed transaction for other orphaned transactions that use the input and invalidate them.
    '''
    def __init__(self, spv):
        self.spv = spv
        self.transaction_database_file = self.spv.config.get_file("txdb")
        self.db_lock = threading.Lock()
        self.transaction_cache = {}

        self.blockchain_height = self.spv.blockchain.best_chain['height']

        with closing(shelve.open(self.transaction_database_file)) as txdb:
            for tx_hash_str in list(txdb.keys()):
                if tx_hash_str.startswith('tx-'):
                    if self.spv.args.resync:
                        txdb.pop(tx_hash_str)
                    else:
                        self.transaction_cache[hexstring_to_bytes(tx_hash_str[3:])] = txdb[tx_hash_str]

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
            if tx_hash in self.transaction_cache:
                return

            with closing(shelve.open(self.transaction_database_file)) as txdb:
                tx_hash_str = 'tx-' + bytes_to_hexstring(tx_hash)

                txdb[tx_hash_str] = {
                    'data'     : tx.serialize(),
                    'in_blocks': set(),
                }

                self.transaction_cache[tx_hash] = {
                    'in_blocks': set(),
                }

            #! for i, input in tx.inputs:
            #!     self.watched_inputs ...

    def bind_tx(self, tx_hash, block_hash):
        '''associate a block with a transaction; i.e., tx was found in this block. bind_tx needs to be called on each relevent transaction
        before any calls to on_block_added'''
        with self.db_lock:
            if tx_hash not in self.transaction_cache:
                return

            return self.__bind_txns([tx_hash], block_hash)

    def __bind_txns(self, tx_hashes, block_hash):
        with closing(shelve.open(self.transaction_database_file)) as txdb:
            for tx_hash in tx_hashes:
                self.transaction_cache[tx_hash]['in_blocks'].add(block_hash)

                tx_hash_str = 'tx-' + bytes_to_hexstring(tx_hash)
                tx_dict = txdb[tx_hash_str]
                tx_dict['in_blocks'].add(block_hash)
                txdb[tx_hash_str] = tx_dict

                if block_hash not in self.watched_block_height:
                    self.watched_block_height[block_hash] = 0
                    txdb['watched_block_height'] = self.watched_block_height

                if self.spv.logging_level <= DEBUG:
                    print('[TXDB] bound tx {} to block {}'.format(tx_hash_str[3:], bytes_to_hexstring(block_hash)))

    def get_tx_depth(self, tx_hash):
        with self.db_lock:
            if tx_hash not in self.transaction_cache:
                if self.spv.logging_level <= WARNING:
                    print("[TXDB] get_tx_depth called on tx {} but we don't know about it".format(bytes_to_hexstring(tx_hash)))
                return 0
            for block_hash in self.transaction_cache[tx_hash]['in_blocks']:
                h = self.watched_block_height[block_hash]
                if h != 0:
                    return self.blockchain_height - h + 1
            return 0 

    def is_conflicted(self, tx_hash):
        with self.db_lock:
            if tx_hash not in self.transaction_cache:
                return False

            for block_hash in self.transaction_cache[tx_hash]['in_blocks']:
                h = self.watched_block_height[block_hash]
                if h != 0:
                    # There's at least 1 block in the blockchain that includes this transaction, so this can't be a conflicting transaction right now
                    return False

                # TODO check to see if inputs are seen in the blockchain at a depth greather than X...

        return False

    def on_block_removed(self, block_header, block_height):
        block_hash = block_header.hash()
        with self.db_lock:
            self.blockchain_height -= 1
            if block_hash in self.watched_block_height:
                self.watched_block_height[block_hash] = 0
                with closing(shelve.open(self.transaction_database_file)) as txdb:
                    txdb['watched_block_height'] = self.watched_block_height

    def on_block_added(self, block_header, block_height):
        block_hash = block_header.hash()
        with self.db_lock:
            self.blockchain_height += 1
            if block_hash in self.watched_block_height:
                self.watched_block_height[block_hash] = self.blockchain_height
                with closing(shelve.open(self.transaction_database_file)) as txdb:
                    txdb['watched_block_height'] = self.watched_block_height
                if self.spv.logging_level <= DEBUG:
                    print('[TXDB] block {} tracked starting at height={}'.format(bytes_to_hexstring(block_hash), self.blockchain_height))

    def on_tx(self, tx):
        # Don't care.
        pass
    
    def on_block(self, block):
        with self.db_lock:
            tx_hashes = [ tx.hash() for tx in block.transactions ]
            self.__bind_txns((tx_hash for tx_hash in tx_hashes if tx_hash in self.transaction_cache), block.header.hash())

