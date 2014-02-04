import os
import time

from . import blockchain
from . import inv
from . import keys
from . import network
from . import txdb
from . import wallet

from .bitcoin import *
from .util import *
from .monitors.pubkey import PubKeyTransactionBuilder, PubKeyPaymentMonitor

VERSION = 'pyspv 0.0.1-alpha1'

class pyspv:
    class config:
        def __init__(self, name, testnet=False):
            if os.name != 'nt':
                name = '.' + name

            e = os.getenv("APPDATA")
            if e is not None:
                self.path = os.sep.join([e, name])
            else:
                self.path = os.sep.join([os.path.expanduser("~"), name])
            
            if not os.path.exists(self.path):
                os.mkdir(self.path)

            if testnet:
                self.path = os.sep.join([self.path, 'testnet'])
                if not os.path.exists(self.path):
                    os.mkdir(self.path)

        def get_file(self, f):
            return os.sep.join([self.path, f])

    class callbacks:
        def __init__(self, on_tx=None, on_block=None, on_block_added=None, on_block_removed=None):
            self.on_tx            = on_tx
            self.on_block         = on_block
            self.on_block_added   = on_block_added
            self.on_block_removed = on_block_removed

    def __init__(self, app_name, testnet=False, peer_goal=8, logging_level=WARNING, on_tx=None, on_block=None, on_block_added=None, on_block_removed=None):
        self.app_name = app_name
        self.time_offset = 0
        self.logging_level = logging_level
        self.testnet = testnet
        self.time_samples = []

        self.coin = BitcoinTestnet if testnet else Bitcoin

        self.callbacks = pyspv.callbacks(on_tx=on_tx, on_block=on_block, on_block_added=on_block_added, on_block_removed=on_block_removed)
        self.config = pyspv.config(app_name, testnet=testnet)

        if self.logging_level <= DEBUG:
            print('[PYSPV] app data at {}'.format(self.config.path))

        self.wallet = wallet.Wallet(spv=self, monitors=[PubKeyPaymentMonitor])

        self.blockchain = blockchain.Blockchain(spv=self)

        self.txdb = txdb.TransactionDatabase(spv=self)

        self.network_manager = network.Manager(spv=self, peer_goal=peer_goal, callbacks=self.callbacks)
        self.network_manager.start()

    def shutdown(self):
        self.network_manager.shutdown()
    
    def join(self):
        self.network_manager.join()

    def adjusted_time(self):
        return self.time() + self.time_offset

    def add_time_data(self, peer_time):
        now = time.time()
        offset = peer_time - now
        self.time_samples.append(offset)
        if len(self.time_samples) >= 5 and (len(self.time_samples) % 2) == 1:
            m = list(sorted(self.time_samples))[(len(self.time_samples) // 2) + 1]
            if abs(m) < 70 * 60:
                if self.logging_level <= DEBUG:
                    print('[PYSPV] peer time offset = {} sec'.format(m))
                self.time_offset = m
            else:
                # TODO - we should inform the app that we can't get good time data
                self.time_offset = 0

    def broadcast_transaction(self, tx, must_confirm=False):
        # Let wallet see the tx...
        #self.on_tx(tx)

        # In case the wallet didn't save the tx...
        if must_confirm:
            self.txdb.save_tx(tx)

        # Broadcast it
        tx_inv = inv.Inv(inv.Inv.MSG_TX, tx.hash())
        self.network_manager.add_to_inventory(tx_inv, tx, network.Manager.INVENTORY_FLAG_MUST_CONFIRM if must_confirm else 0)

    def on_tx(self, tx):
        if self.callbacks is not None and self.callbacks.on_tx is not None:
            if self.callbacks.on_tx(tx):
                return

        self.wallet.on_tx(tx)

    def on_block(self, block):
        if self.callbacks is not None and self.callbacks.on_block is not None:
            if self.callbacks.on_block(block):
                return

        block_hash = block.header.hash()
        for tx in block.transactions:
            # Calling on_tx allows the wallet to process the transaction and eventually call txdb.save_tx so
            # that bind_tx works successfully
            self.on_tx(tx)
            self.txdb.bind_tx(tx.hash(), block_hash)

    def on_block_added(self, block_hash):
        if self.callbacks is not None and self.callbacks.on_block_added is not None:
            if self.callbacks.on_block_added(block_hash):
                return

        self.txdb.on_block_added(block_hash)
        # block_link = self.blockchain.blocks[block_hash] ...

    def on_block_removed(self, block_hash):
        if self.callbacks is not None and self.callbacks.on_block_removed is not None:
            if self.callbacks.on_block_removed(block_hash):
                return

        self.txdb.on_block_removed(block_hash)
        block_link = self.blockchain.blocks[block_hash]
        # TODO confirmations

