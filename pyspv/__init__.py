from . import network
from .util import *

class pyspv:
    def __init__(self, logging_level=WARNING):
        self.network_manager = network.MANAGER(logging_level=logging_level)
        self.network_manager.start()

    def shutdown(self):
        self.network_manager.shutdown()
    
    def join(self):
        self.network_manager.join()
