import argparse
import ipaddress
import sys
import time

from . import blockchain
from . import inv
from . import keys
from . import network
from . import script
from . import transaction
from . import transactionbuilder
from . import txdb
from . import wallet

from .bitcoin import *

from .monitors.pubkey import PubKeyPaymentMonitor
from .monitors.multisig import MultisigScriptHashPaymentMonitor

from .payments import PubKeyChange, PubKeyPayment, ScriptHashPayment

from .util import *

VERSION = 'pyspv 0.0.1-alpha1'
VERSION_NUMBER = 0x00000101

class pyspv:
    '''SPV encapsulation class.  One instance of this class is enough to manage a wallet, transactions,
    network. blockchain, etc.

    :param app_name: a name of your application; this name will be used in the path to application data
    :type app_name: string
    :param testnet: enables testnet for the specified coin
    :type testnet: boolean
    :param logging_level: the print logging level
    :type logging_level: DEBUG, INFO, WARNING, ERROR, or CRITICAL
    :param peer_goal: target number of peers to maintain connections with
    :type peer_goal: integer
    :param listen: the listen address to be used with socket.bind
    :type listen: tuple (string, integer)
    :param coin: the coin definition
    :type coin: coin class
    '''

    def __init__(self, app_name, testnet=False, peer_goal=8, logging_level=WARNING, listen=('', 0), coin=Bitcoin, tor=False):
        '''
        '''
        self.app_name = app_name
        self.time_offset = 0
        self.logging_level = logging_level
        self.testnet = testnet
        self.time_samples = []

        # Command-line arguments can override constructor args
        self.args = self.__parse_arguments()

        if self.args.testnet:
            testnet = True

        if self.args.tor:
            tor = True

        self.coin = coin.Testnet if testnet else coin

        self.config = Config(app_name, self.coin, testnet=testnet)

        if self.logging_level <= DEBUG:
            print('[PYSPV] app data at {}'.format(self.config.path))

        # It's important that the txdb be available before the wallet loads (computing balance requires knowing confirmations in the spends)
        # And the txdb requires the blockchain to be loaded
        self.blockchain = blockchain.Blockchain(spv=self)
        self.txdb = txdb.TransactionDatabase(spv=self)

        self.wallet = wallet.Wallet(spv=self, monitors=[PubKeyPaymentMonitor, MultisigScriptHashPaymentMonitor])
        self.wallet.load()

        self.network_manager = network.Manager(spv=self, peer_goal=peer_goal, listen=listen, tor=tor)
        self.network_manager.start()

    def __parse_arguments(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--resync', action='store_const', default=False, const=True)
        parser.add_argument('--testnet', action='store_const', default=False, const=True)
        parser.add_argument('--tor', action='store_const', default=False, const=True)
        parser.add_argument('--torproxy', type=str, default=None, help='specify tor proxy (default 127.0.0.1:9050, implies --tor)')
        args, remaining = parser.parse_known_args()
        sys.argv = [sys.argv[0]] + remaining

        if args.torproxy is not None:
            if ':' in args.torproxy:
                addr, port = args.torproxy.split(':')
                port = int(port)
            else:
                addr = args.torproxy
                port = 9050

            # Raise an exception if the provided address is invalid
            ipaddress.IPv4Address(addr)
            assert 0 <= port <= 65535
            args.torproxy = (addr, port)
            args.tor = True
        else:
            args.torproxy = ('127.0.0.1', 9050)

        return args

    def shutdown(self):
        '''Initiate asynchronous shutdown.  This peacefully disconnects from network peers and saves all necessary data.

        After calling :py:meth:`~pyspv.shutdown`, you may call :py:meth:`~pyspv.join` to block on shutdown.'''
        self.network_manager.shutdown()
    
    def join(self):
        '''Block until shutdown is complete.  If :py:meth:`~pyspv.shutdown` hasn't been called yet, this function will block forever.'''
        self.network_manager.join()

    def adjusted_time(self):
        '''
        :returns: Returns network adjusted time.'''
        return self.time() + self.time_offset

    def add_time_data(self, peer_time):
        '''Add *peer_time* as an input to determine network adjusted timestamps.  You generally don't need to call this,
        as it's intended to only be used by the Network code.  Incorrectly adjusting network time could cause your node
        to misbehave.'''
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

    def new_transaction_builder(self, memo=''):
        '''Creates a new transaction builder.

        :param memo: TODO
        :returns: Returns a new :py:class:`pyspv.transactionbuilder.TransactionBuilder`
        '''
        return transactionbuilder.TransactionBuilder(self, memo=memo)

    def broadcast_transaction(self, tx, must_confirm=False):
        # Let wallet see the tx...
        self.on_tx(tx)

        # In case the wallet didn't save the tx...
        if must_confirm:
            self.txdb.save_tx(tx)

        # Broadcast it
        tx_inv = inv.Inv(inv.Inv.MSG_TX, tx.hash())
        self.network_manager.add_to_inventory(tx_inv, tx, network.Manager.INVENTORY_FLAG_MUST_CONFIRM if must_confirm else 0)

    def on_tx(self, tx):
        '''Called for every transaction seen on the network, not including those found in blocks.

        If you override this method, be sure to call :py:meth:`pyspv.on_tx`. Otherwise, the wallet will not see any payments.'''
        self.wallet.on_tx(tx)
        self.txdb.on_tx(tx)

    def on_block(self, block):
        '''Called for every block seen on the network, whether it ends up part of the blockchain or not.

        If you override this method, be sure to call :py:meth:`pyspv.on_block`.  Otherwise, the wallet will not see payments in this block.

        .. note:: 
           
           This function is not called for block headers syncing, only full blocks.
        '''
        self.wallet.on_block(block)
        self.txdb.on_block(block)

    def on_block_added(self, block_header, block_height):
        '''Called when the blockchain is extended to a height of *block_height* with the block specified by *block_header*.

        If you override this method, you must call :py:meth:`pyspv.on_block_added`, otherwise the transaction database
        will not function properly.

        .. note::

           Called for both full blocks and block headers, but only when this *block_header* refers to an actual
           new link in the blockchain.  
        '''
        self.txdb.on_block_added(block_header, block_height)

    def on_block_removed(self, block_header, block_height):
        '''Called when the blockchain is reduced from a height of *block_height* by removing the block specified by *block_header*.

        If you override this method, you must call :py:meth:`pyspv.on_block_removed`, otherwise the transaction database
        will not function properly.
        '''
        self.txdb.on_block_removed(block_header, block_height)

