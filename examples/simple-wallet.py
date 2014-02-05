import json
import pyspv
import sys
import time
import traceback

import xmlrpc.client 
from xmlrpc.server import SimpleXMLRPCServer

RPC_LISTEN_ADDRESS = '127.0.0.1'
RPC_LISTEN_PORT    = 18899

spv = None

def exception_printer(f):
    def f2(*args, **kwargs):
        nonlocal f
        try:
            return f(*args, **kwargs)
        except:
            traceback.print_exc()
            return traceback.format_exc()
    f2.__name__ = f.__name__
    return f2

@exception_printer
def getinfo():
    return {
        'balance': spv.coin.format_money(sum(v for v in spv.wallet.balance.values())),
        'blocks': spv.blockchain.best_chain['height'],
        'version': pyspv.VERSION,
        'platform': sys.platform,
        'python': sys.version,
        'user-agent': '',
        'app-name': spv.app_name,
        'testnet': spv.testnet,
        'coin': spv.coin.__name__,
    }

@exception_printer
def sendtoaddress(address, amount, memo=''):
    address_bytes = int.to_bytes(pyspv.base58.decode(address), spv.coin.ADDRESS_BYTE_LENGTH, 'big')
    k = len(spv.coin.ADDRESS_VERSION_BYTES)
    if address_bytes[:k] == spv.coin.ADDRESS_VERSION_BYTES:
        payment_builder = pyspv.PubKeyTransactionBuilder(spv.wallet, memo=memo)
        payment_builder.add_recipient(address, spv.coin.parse_money(amount))
        tx = payment_builder.finish(True, True)
        if not tx.verify_scripts():
            raise Exception("internal error building transaction")
        spv.broadcast_transaction(tx)
        return pyspv.bytes_to_hexstring(tx.hash())

    return "error: bad address {}".format(address)

@exception_printer
def getbalance():
    return dict((k, spv.coin.format_money(v)) for k, v in spv.wallet.balance.items())

@exception_printer
def getnewaddress(label='', compressed=0):
    compressed = bool(int(compressed))
    pk = pyspv.keys.PrivateKey.create_new()
    spv.wallet.add('private_key', pk, {'label': label})
    return pk.get_public_key(compressed).as_address(spv.coin)

@exception_printer
def listspends():
    s = [str(spend['spend']) for spend in spv.wallet.spends.values()]
    return '\n'.join(s)

def server_main():
    global spv

    spv = pyspv.pyspv('pyspv-simple-wallet', logging_level=pyspv.DEBUG, peer_goal=0, testnet=True, listen=('0.0.0.0', 8336))
                #listen=None,
                #proxy=...,
                #relay_tx=False,

    rpc_server = SimpleXMLRPCServer((RPC_LISTEN_ADDRESS, RPC_LISTEN_PORT), allow_none=True)
    rpc_server.register_function(getnewaddress)
    rpc_server.register_function(getbalance)
    rpc_server.register_function(sendtoaddress)
    rpc_server.register_function(getinfo)
    rpc_server.register_function(listspends)

    try:
        rpc_server.serve_forever()
    except KeyboardInterrupt:
        pass

    spv.shutdown() # Async shutdown
    spv.join()     # Wait for shutdown to complete

def rpc_call():
    s = xmlrpc.client.ServerProxy("http://{}:{}".format(RPC_LISTEN_ADDRESS, RPC_LISTEN_PORT))
    response = getattr(s, sys.argv[1])( *sys.argv[2:] )

    if isinstance(response, str) or response is None:
        print(response)
    else:
        print(json.dumps(response))

if __name__ == "__main__":
    if len(sys.argv) == 1 or all(x.startswith('-') for x in sys.argv[1:]):
        try:
            server_main()
        except:
            traceback.print_exc()
    else:
        rpc_call()

