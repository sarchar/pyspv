import pyspv
import time
import traceback

def on_tx(tx):
    return False

def main():
    spv = pyspv.pyspv('pyspv-simple-wallet', logging_level=pyspv.DEBUG, peer_goal=4, testnet=True)
                #listen=('0.0.0.0', 8334),
                #listen=None,
                #proxy=...,
                #relay_tx=False,
 
    if len(list(spv.wallet.private_keys())) == 0:
        spv.wallet.create_new_private_key()

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

