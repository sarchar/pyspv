pyspv
=====

__WARNING__: *This is experimental software. Use at your own risk*

pyspv is a no-bullshit, easy-to-use Python module implementing the full Bitcoin
SPV client protocol.  Connecting to the Bitcoin network is as easy as:

```python
import pyspv
spv = pyspv.pyspv("my-application-name")
...
```

... but just connecting to the Bitcoin network would be boring.  The real goal
of this project is to make embedding Bitcoin into your project so simple that
everybody does it.  pyspv handles the details like Blockchain syncing, the
peer-to-peer network, payment management, wallets, etc., and allows you to get
started prototyping your Bitcoin application quickly.

I intend to make this SPV client as extensible as possible with a goal of
supporting alt-coins using simple coin definitions.  Because pyspv is modular,
it is now easy to connect to several different alt-coin networks within the
same application -- simply initialize two pyspv classes with different coin
definitions.

You can develop a pretty UI wallet or just a simple utility to send you an
E-mail you when an address receives a payment. The possibilities are really
endless.

requirements
============

pyspv only relies on a small handful of dependencies:

* [Python 3.3](http://www.python.org/) :: It probably works on other versions, but this is my testing platform.
* OpenSSL :: You'll need libssl.so (Linux/Mac) or libeay32.dll (Windows) in your path.
* [Bitarray](https://pypi.python.org/pypi/bitarray/) :: This is required by the bloom filter implementation.

features
========

* SPV implementation, so relatively lightweight
* Python, useful for server and user applications
* Multisignature support, can create, send to and spend multisignature payments
* Stealth address support, can create, send to and spend stealth address payments
* Tor/SOCKS support
* Testnet support
* Extensible payment monitor and transaction building system

examples
========

simple-wallet.py
----------------

This example runs a basic wallet.  Running it with no arguments starts an RPC
server.  With arguments, an RPC call is made.  The program behaves similarly to
bitcoind, with several noticeable differences.

Available commands:

* getnewaddress \[label\]? - returns a standard public-key-hash address
* getnewstealthaddress \[label\]? - returns a new stealth address
* getnewpubkey \[label\]? \[compressed=false\]? - returns a new public key (hex)
* getbalance - returns total balance in the wallet
* getinfo - returns information on the state of the SPV node
* listspends \[include\_spent=false\] - returns a dictionary describing the Spends in the wallet
* sendtoaddress \[address\] \[amount\] \[memo\]? - sends amount of coins to address. The address can be a stealth address, a multisig address, or a standard address.
* sendspendtoaddress \[spend\_hash\] \[address\] \[amount\] \[memo\]? - force inclusion of a specific Spend to the specified address. more coins are selected from the wallet if they're needed to complete the transaction.
* dumppubkey \[address\] - yield the public key of the specified address, if it's in the wallet
* dumpprivkey \[address\] - yield the private key (in WIF format) of the specified address, if it's in the wallet
* genmultisig \[nreq\] \[mtotal\] \[pubkey1,pubkey2,...\]? - produce a new multsignature address. If not mtotal public keys are provided, new ones are generated and stored in the wallet. The multisignature address requires nreq signatures to spend.
* sendrawtransaction \[tx\_hex\] - broadcast a transaction to the network

test-stealth-keys.py
--------------------

This example runs through the math and demonstrates how stealth addresses work in theory.  

anyonecanpay-new.py
-------------------

Create a new transaction with specified outputs and zero inputs.  The transaction displayed can be used as input to anyonecanpay-add.py.

anyonecanpay-add.py
-------------------

Given a transaction and a spend id, add those inputs and sign them using ANYONECANPAY.  This program, combined with anyonecanpay-new.py
effectly allows easy creation of [assurance contracts](https://en.bitcoin.it/wiki/Contracts#Example_3:_Assurance_contracts).

documentation
=============

TODO

Documentation will soon be available at http://docs.pyspv.org/

