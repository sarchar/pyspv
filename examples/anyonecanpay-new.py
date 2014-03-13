import pyspv
import sys
import traceback

def main():
    simple_wallet = __import__('simple-wallet')

    # We need a wallet, but don't need a network. Set peer_goal to 0
    spv = pyspv.pyspv('pyspv-simple-wallet', logging_level=pyspv.INFO, peer_goal=0, listen=None)

    tx = pyspv.transaction.Transaction(spv.coin)
    total_output = 0

    for i in range(1, len(sys.argv), 2):
        address = sys.argv[i]
        amount  = sys.argv[i+1]
        
        output_producer = simple_wallet.get_output_producer(spv, address, spv.coin.parse_money(amount))
        for output in output_producer.create_outputs(spv):
            tx.outputs.append(output)
            total_output += output.amount

    print(pyspv.bytes_to_hexstring(tx.serialize(), reverse=False))
    print("total transaction output: {}".format(spv.coin.format_money(total_output)))

    spv.shutdown() # Async shutdown
    spv.join()     # Wait for shutdown to complete

if __name__ == "__main__":
    try:
        main()
    except:
        traceback.print_exc()

