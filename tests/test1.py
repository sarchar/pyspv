import pyspv
import time
import traceback

def main():
    spv = pyspv.pyspv(logging_level=pyspv.DEBUG)
                #listen=('0.0.0.0', 8334),
                #listen=None,
                #proxy=...,
                #testnet=True,
                #peer_goal=20,
    
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

