import pyspv
import sys
import threading
import time

def main():
    num_threads = 1 if len(sys.argv) < 2 else int(sys.argv[1])

    coin = pyspv.Bitcoin
    spv = pyspv.pyspv('solve-genesis', logging_level=pyspv.DEBUG, peer_goal=0, listen=None, coin=coin)

    pk = pyspv.keys.PrivateKey.create_new()
    spv.wallet.add('private_key', pk, {'label': ''})
    #pk.get_public_key(compressed).as_address(spv.coin)

    # build coinbase
    outscript = pyspv.script.Script()
    outscript.push_op(pyspv.script.OP_DUP)
    outscript.push_op(pyspv.script.OP_HASH160)
    outscript.push_bytes(pk.get_public_key(True).as_hash160(coin))
    outscript.push_op(pyspv.script.OP_EQUALVERIFY)
    outscript.push_op(pyspv.script.OP_CHECKSIG)
    out1 = pyspv.transaction.TransactionOutput(amount=coin.STARTING_BLOCK_REWARD, script=outscript)

    prevout = pyspv.transaction.TransactionPrevOut(tx_hash=(b'\x00' * 32), n=0xffffffff)
    inscript = pyspv.script.Script()
    inscript.program = b''
    in1 = pyspv.transaction.TransactionInput(prevout=prevout, script=inscript)

    tx = pyspv.transaction.Transaction(coin)
    tx.inputs.append(in1)
    tx.outputs.append(out1)
    assert tx.is_coinbase()

    block = pyspv.block.Block(coin)
    block.transactions.append(tx)
    block.header.version = coin.GENESIS_BLOCK_VERSION
    block.header.prev_block_hash = (b'\x00' * 32)
    block.header.merkle_root_hash = block.calculate_merkle_root()
    block.header.timestamp = coin.GENESIS_BLOCK_TIMESTAMP
    block.header.bits = coin.GENESIS_BLOCK_BITS

    solution = None
    def solver(block_header):
        nonlocal solution
        while solution is None and not block_header.check():
            block_header.nonce += 1
            if (block_header.nonce % 10000) == 0:
                print(block_header.nonce)
        solution = block_header

    headers = [pyspv.block.BlockHeader.unserialize(block.header.serialize(), coin)[0] for _ in range(num_threads)]
    for i, header in enumerate(headers):
        header.nonce = (i * ((1<<32) // num_threads) & 0xffffffff)

    threads = [threading.Thread(target=solver, args=(headers[i],)) for i in range(num_threads-1)]

    for thr in threads:
        thr.start()

    solver(headers[-1])

    print(pyspv.bytes_to_hexstring(solution.serialize(), reverse=False))
    print(pyspv.bytes_to_hexstring(solution.hash()))

    spv.shutdown() # Async shutdown
    spv.join()     # Wait for shutdown to complete

if __name__ == "__main__":
    main()

