
class BaseMonitor:
    def __init__(self, spv):
        self.spv = spv

    def on_tx(self, tx):
        raise NotImplementedError("Implement me")

