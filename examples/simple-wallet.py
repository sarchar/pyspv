import pyspv
import time
import traceback

def on_tx(tx):
    return False

def main():
    spv = pyspv.pyspv('pyspv-simple-wallet', logging_level=pyspv.DEBUG, peer_goal=8, testnet=True)
                #listen=('0.0.0.0', 8334),
                #listen=None,
                #proxy=...,
                #relay_tx=False,

    # Make sure we have at least 10 addresses
    while spv.wallet.len('private_key') < 10:
        pk = pyspv.keys.PrivateKey.create_new()
        spv.wallet.add('private_key', pk, {'label': ''})

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    spv.shutdown() # Async shutdown
    spv.join()     # Wait for shutdown to complete

if __name__ == "__main__":
    try:
        main()
    except:
        traceback.print_exc()

