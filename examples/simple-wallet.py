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

def get_output_producer(spv, address, amount):
    # Determine the payment type based on the version byte of the address provided
    # (I don't think this is the proper long term solution to different payment types...)
    try:
        address_bytes = int.to_bytes(pyspv.base58.decode(address), spv.coin.ADDRESS_BYTE_LENGTH, 'big')
    except OverflowError:
        address_bytes = b''

    k = len(spv.coin.ADDRESS_VERSION_BYTES)
    if address_bytes[:k] == spv.coin.ADDRESS_VERSION_BYTES:
        return pyspv.PubKeyPayment(address, amount)
    else:
        try:
            address_bytes = int.to_bytes(pyspv.base58.decode(address), spv.coin.P2SH_ADDRESS_BYTE_LENGTH, 'big')
        except OverflowError:
            address_bytes = b''

        k = len(spv.coin.P2SH_ADDRESS_VERSION_BYTES)
        if address_bytes[:k] == spv.coin.P2SH_ADDRESS_VERSION_BYTES:
            return pyspv.MultisigScriptHashPayment(address, amount)
        else:
            try:
                # Drop last 4 bytes because of the checksum
                address_bytes = int.to_bytes(pyspv.base58.decode(address), spv.coin.STEALTH_ADDRESS_BYTE_LENGTH, 'big')[:-4]
            except OverflowError:
                address_bytes = b''

            k = len(spv.coin.STEALTH_ADDRESS_VERSION_BYTES)
            j = len(spv.coin.STEALTH_ADDRESS_SUFFIX_BYTES)
            if address_bytes[:k] == spv.coin.STEALTH_ADDRESS_VERSION_BYTES and address_bytes[-j:] == spv.coin.STEALTH_ADDRESS_SUFFIX_BYTES: 
                return pyspv.StealthAddressPayment(address, amount)
            else:
                raise Exception("error: bad address {}".format(address))

@exception_printer
def sendtoaddress(address, amount, memo=''):
    transaction_builder = spv.new_transaction_builder(memo=memo)
    transaction_builder.process_change(pyspv.PubKeyChange)
    transaction_builder.process(get_output_producer(spv, address, spv.coin.parse_money(amount)))
    tx = transaction_builder.finish(shuffle_inputs=True, shuffle_outputs=True)

    if not tx.verify_scripts():
        raise Exception("internal error building transaction")

    spv.broadcast_transaction(tx)

    return {
        'tx': pyspv.bytes_to_hexstring(tx.serialize(), reverse=False),
        'hash': pyspv.bytes_to_hexstring(tx.hash()),
    }

@exception_printer
def sendspendtoaddress(spend_hash, address, amount, memo=''):
    spend_hash = pyspv.hexstring_to_bytes(spend_hash)
    transaction_builder = spv.new_transaction_builder(memo=memo)
    transaction_builder.include_spend(spend_hash)
    transaction_builder.process_change(pyspv.PubKeyChange)
    transaction_builder.process(get_output_producer(spv, address, spv.coin.parse_money(amount)))
    tx = transaction_builder.finish(shuffle_inputs=True, shuffle_outputs=True)

    if not tx.verify_scripts():
        raise Exception("internal error building transaction")

    spv.broadcast_transaction(tx)

    return {
        'tx': pyspv.bytes_to_hexstring(tx.serialize(), reverse=False),
        'hash': pyspv.bytes_to_hexstring(tx.hash()),
    }

@exception_printer
def getbalance():
    return dict((k, spv.coin.format_money(v)) for k, v in spv.wallet.balance.items())

@exception_printer
def getnewaddress(label='', compressed=False):
    if str(compressed).lower() in ('1', 'true'):
        compressed = True
    else:
        compressed = False

    pk = pyspv.keys.PrivateKey.create_new()
    spv.wallet.add('private_key', pk, {'label': label})
    return pk.get_public_key(compressed).as_address(spv.coin)

@exception_printer
def getnewstealthaddress(label=''):
    pk = pyspv.keys.PrivateKey.create_new()
    spv.wallet.add('private_key', pk, {'label': label, 'stealth_payments': True})
    return pyspv.base58_check(spv.coin, pk.get_public_key(True).pubkey, version_bytes=spv.coin.STEALTH_ADDRESS_VERSION_BYTES, suffix_bytes=spv.coin.STEALTH_ADDRESS_SUFFIX_BYTES)

@exception_printer
def getnewpubkey(label='', compressed=False):
    if str(compressed).lower() in ('1', 'true'):
        compressed = True
    else:
        compressed = False

    pk = pyspv.keys.PrivateKey.create_new()
    spv.wallet.add('private_key', pk, {'label': label})
    return pk.get_public_key(compressed).as_hex()

@exception_printer
def listspends(include_spent=False):
    result = {
        'spendable': [],
        'not_spendable': [],
    }

    if str(include_spent).lower() in ('1', 'true'):
        include_spent = True
        result['spent'] = []
    else:
        include_spent = False

    def f(spend):
        r = {
            'id': pyspv.bytes_to_hexstring(spend.hash()),
            'class': spend.__class__.__name__,
            'amount': spv.coin.format_money(spend.amount),
            'confirmations': spend.get_confirmations(spv),
        }

        if hasattr(spend, 'prevout'):
            r['prevout'] = {
                'txid': pyspv.bytes_to_hexstring(spend.prevout.tx_hash),
                'n'   : spend.prevout.n
            }

        if hasattr(spend, 'address'):
            r['address'] = spend.address

        return r

    for spend in spv.wallet.spends.values():
        is_spent = spend['spend'].is_spent(spv)
        if not include_spent and is_spent:
            continue

        if is_spent:
            result['spent'].append(f(spend['spend']))
        elif spend['spend'].is_spendable(spv):
            result['spendable'].append(f(spend['spend']))
        else:
            result['not_spendable'].append(f(spend['spend']))#str(spend['spend']) + ', confirmations={}'.format(spend['spend'].get_confirmations(spv)))

    return result
    #return 'Spendable:\n' + '\n'.join(spendable) + '\nNot Spendable ({} confirmations required):\n'.format(spv.coin.TRANSACTION_CONFIRMATION_DEPTH) + '\n'.join(not_spendable)

@exception_printer
def dumppubkey(address):
    '''PubKeyPaymentMonitor has to be included for this to work'''
    metadata = spv.wallet.get_temp('address', address)
    if metadata is None:
        return 'error: unknown address'

    return metadata['public_key'].as_hex()

@exception_printer
def dumpprivkey(address_or_pubkey):
    '''PubKeyPaymentMonitor has to be included for this to work'''
    metadata = spv.wallet.get_temp('address', address_or_pubkey)
    if metadata is not None:
        public_key = metadata['public_key']
    else:
        public_key = pyspv.keys.PublicKey.from_hex(address_or_pubkey)

    metadata = spv.wallet.get_temp('public_key', public_key)
    if metadata is None:
        return 'error: unknown key'
    return metadata['private_key'].as_wif(spv.coin, public_key.is_compressed())

@exception_printer
def genmultisig(nreq, mtotal, *pubkeys):
    '''Generate a new multisignature address and redemption script that requires `nreq' signatures to spend and provides a possible `mtotal'.
    If public keys are provided on the command line, those are used instead of generating new ones.'''

    nreq = int(nreq)
    mtotal = int(mtotal)
    pubkeys = list(pubkeys)
    assert 0 <= nreq <= mtotal
    assert len(pubkeys) <= mtotal

    # Create new keys if necessary
    while len(pubkeys) < mtotal:
        pk = pyspv.keys.PrivateKey.create_new()
        spv.wallet.add('private_key', pk, {'label': ''})
        pubkeys.append(pk.get_public_key(compressed=True).as_hex())

    pubkeys = [pyspv.keys.PublicKey.from_hex(pubkey) for pubkey in pubkeys]
    pubkeys.sort()

    # build the M-of-N multisig redemption script and add it to the wallet
    # (the p2sh monitor will notice that we added a redemption script to the 
    # wallet and start watching for transactions to it

    script = pyspv.script.Script()
    script.push_int(nreq)

    for pubkey in pubkeys:
        script.push_bytes(pubkey.pubkey)

    script.push_int(len(pubkeys))
    script.push_op(pyspv.script.OP_CHECKMULTISIG)

    redemption_script = script.program
    address = pyspv.base58_check(spv.coin, spv.coin.hash160(redemption_script), version_bytes=spv.coin.P2SH_ADDRESS_VERSION_BYTES)

    try:
        spv.wallet.add('redemption_script', redemption_script, {})
    except pyspv.wallet.DuplicateWalletItem:
        # No worries, we already have this redemption script
        if spv.logging_level <= pyspv.INFO:
            print('[simple-wallet] Duplicate redemption script??')
        pass

    return {
        'address': address,
        'redemption_script': pyspv.bytes_to_hexstring(redemption_script, reverse=False),
        'pubkeys': [ pubkey.as_hex() for pubkey in pubkeys ],
        'nreq': nreq,
    }

@exception_printer
def sendrawtransaction(tx_bytes):
    tx_bytes = pyspv.hexstring_to_bytes(tx_bytes, reverse=False)
    tx, _ = pyspv.transaction.Transaction.unserialize(tx_bytes, spv.coin)
    spv.broadcast_transaction(tx)
    return pyspv.bytes_to_hexstring(tx.hash())

def server_main():
    global spv

    logging_level = pyspv.WARNING
    if '-v' in sys.argv:
        logging_level = pyspv.INFO
    if '-vv' in sys.argv or '-vvv' in sys.argv:
        logging_level = pyspv.DEBUG

    spv = pyspv.pyspv('pyspv-simple-wallet', logging_level=logging_level, peer_goal=4, testnet=True, listen=('0.0.0.0', 8336))
                #relay_tx=False,

    rpc_server = SimpleXMLRPCServer((RPC_LISTEN_ADDRESS, RPC_LISTEN_PORT), allow_none=True)
    rpc_server.register_function(getnewaddress)
    rpc_server.register_function(getnewstealthaddress)
    rpc_server.register_function(getnewpubkey)
    rpc_server.register_function(getbalance)
    rpc_server.register_function(sendtoaddress)
    rpc_server.register_function(sendspendtoaddress)
    rpc_server.register_function(getinfo)
    rpc_server.register_function(listspends)
    rpc_server.register_function(dumppubkey)
    rpc_server.register_function(dumpprivkey)
    rpc_server.register_function(genmultisig)
    rpc_server.register_function(sendrawtransaction)

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

