
class BaseMonitor:
    def __init__(self, spv):
        self.spv = spv

    def on_block(self, block):
        '''Default implementation'''
        for tx in block.transactions:
            self.on_tx(tx)

    def on_tx(self, tx):
        raise NotImplementedError("Implement me")

