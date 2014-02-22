import pyspv
import sys
import traceback

def main():
    simple_wallet = __import__('simple-wallet')

    # We need a wallet, but don't need a network. Set peer_goal to 0
    spv = pyspv.pyspv('pyspv-simple-wallet', logging_level=pyspv.INFO, peer_goal=0, listen=None)

    tx, _ = pyspv.transaction.Transaction.unserialize(pyspv.hexstring_to_bytes(sys.argv[1], reverse=False), spv.coin)
    input_count = len(tx.inputs)

    for spend_hash in sys.argv[2:]:
        spend_hash = pyspv.hexstring_to_bytes(spend_hash)
        spend = spv.wallet.spends[spend_hash]['spend']

        for input_creator in spend.create_input_creators(spv, pyspv.transaction.Transaction.SIGHASH_ALL | pyspv.transaction.Transaction.SIGHASH_ANYONECANPAY):
            tx.inputs.append(pyspv.transaction.UnsignedTransactionInput(input_creator))

    for i, unsigned_input in enumerate(tx.inputs):
        if isinstance(unsigned_input, pyspv.transaction.UnsignedTransactionInput):
            tx.inputs[i] = unsigned_input.sign(tx, i)

    print(pyspv.bytes_to_hexstring(tx.serialize(), reverse=False))

    spv.shutdown() # Async shutdown
    spv.join()     # Wait for shutdown to complete

if __name__ == "__main__":
    try:
        main()
    except:
        traceback.print_exc()

