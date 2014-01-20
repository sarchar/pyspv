import os

from . import network
from . import txdb
from . import wallet

from .bitcoin import *
from .util import *
from .payments.simple import SimplePayments

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
        def __init__(self, on_tx=None):
            self.on_tx = on_tx

    def __init__(self, app_name, testnet=False, peer_goal=8, logging_level=WARNING, on_tx=None):
        self.coin = BitcoinTestnet if testnet else Bitcoin
        self.testnet = testnet
        self.logging_level = logging_level

        self.callbacks = pyspv.callbacks(on_tx=on_tx)
        self.config = pyspv.config(app_name, testnet=testnet)

        if self.logging_level <= INFO:
            print('[PYSPV] app data at {}'.format(self.config.path))

        self.wallet = wallet.Wallet(spv=self)
        self.wallet.register_payments(SimplePayments(spv=self))
        self.wallet.load_wallet()

        self.txdb = txdb.TransactionDatabase(spv=self)

        self.network_manager = network.Manager(spv=self, peer_goal=peer_goal, callbacks=self.callbacks)
        self.network_manager.start()

    def shutdown(self):
        self.network_manager.shutdown()
    
    def join(self):
        self.network_manager.join()

    def on_tx(self, tx):
        r = False

        if self.callbacks is not None and self.callbacks.on_tx is not None:
            r = self.callbacks.on_tx(tx)

        if not r:
            self.wallet.on_tx(tx)

