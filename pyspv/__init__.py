import os

from . import network
from . import txdb
from . import wallet

from .util import *

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

    def on_tx(self, tx):
        print('saving transaction', str(tx))
        self.txdb.save_tx(tx)

    def __init__(self, app_name, testnet=False, logging_level=WARNING, on_tx=None):
        self.testnet = testnet
        self.logging_level = logging_level

        self.callbacks = pyspv.callbacks(on_tx=self.on_tx if on_tx is None else on_tx)
        self.config = pyspv.config(app_name, testnet=testnet)

        if self.logging_level <= INFO:
            print('[PYSPV] app data at {}'.format(self.config.path))

        self.wallet = wallet.Wallet(spv=self)
        self.txdb = txdb.TransactionDatabase(spv=self)

        self.network_manager = network.Manager(spv=self, callbacks=self.callbacks)
        self.network_manager.start()

    def shutdown(self):
        self.network_manager.shutdown()
    
    def join(self):
        self.network_manager.join()
