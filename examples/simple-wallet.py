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

def getinfo():
    return {
        'balance': spv.coin.format_money(sum(v for v in spv.wallet.balance.values())),
        'blocks': spv.blockchain.best_chain['height'],
        'version': 'TODO',
        'user-agent': '',
        'app-name': spv.app_name,
        'testnet': spv.testnet,
        'coin': spv.coin.__name__,
    }

def sendtoaddress(address, amount, memo=''):
    pass

def getbalance():
    return dict((k, spv.coin.format_money(v)) for k, v in spv.wallet.balance.items())

def getnewaddress(label='', compressed=0):
    compressed = bool(int(compressed))
    pk = pyspv.keys.PrivateKey.create_new()
    spv.wallet.add('private_key', pk, {'label': label})
    return pk.get_public_key(compressed).as_address(spv.coin)

def server_main():
    global spv

    spv = pyspv.pyspv('pyspv-simple-wallet', logging_level=pyspv.DEBUG, peer_goal=0, testnet=True)
                #listen=('0.0.0.0', 8334),
                #listen=None,
                #proxy=...,
                #relay_tx=False,

    rpc_server = SimpleXMLRPCServer((RPC_LISTEN_ADDRESS, RPC_LISTEN_PORT), allow_none=True)
    rpc_server.register_function(getnewaddress)
    rpc_server.register_function(getbalance)
    rpc_server.register_function(sendtoaddress)
    rpc_server.register_function(getinfo)

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
    if len(sys.argv) == 1:
        try:
            server_main()
        except:
            traceback.print_exc()
    else:
        rpc_call()

