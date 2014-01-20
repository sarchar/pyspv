import shelve
import threading

from .util import *

class Wallet:
    '''The Wallet is responsible for managing private keys'''
    def __init__(self, spv=None):
        self.spv = spv
        self.wallet_file = self.spv.config.get_file("wallet")
        self.wallet_lock = threading.Lock()

