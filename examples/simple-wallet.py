import pyspv
import time
import traceback

def on_tx(tx):
    print(str(tx))
    return pyspv.IGNORE_TRANSACTION #pyspv.SAVE_TRANSACTION

def main():
    spv = pyspv.pyspv('pyspv-simple-wallet', logging_level=pyspv.DEBUG, peer_goal=2)
                #listen=('0.0.0.0', 8334),
                #listen=None,
                #proxy=...,
                #testnet=True,
                #peer_goal=20,
                #relay=False,
    
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

