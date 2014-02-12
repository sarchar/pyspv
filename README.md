pyspv
=====

pyspv is a no-bullshit easy-to-use Python module implementing the full Bitcoin
SPV client protocol.  Connecting to the Bitcoin network is as easy as:

```python
import pyspv
spv = pyspv.pyspv("my-application-name")
...
```

... but just connecting to the Bitcoin network would be boring.  The real goal
of this project is to make it so you can just ignore all the protocol details
like Blockchain syncing, the peer-to-peer network, misbehaving peers, payment
management, etc., and get started immediately writing your cryptocoin application.  

I intend to make this SPV client as extensible as possible while supporting as
many alt-coins as possible using simple coin definitions.  You can develop a
pretty UI wallet or just a simple utility to sent you an E-mail you when an
address receives a payment. The possibilities are really endless.

Because pyspv is modular, it is now easy to connect to several different
alt-coin networks within the same application -- simply initialize two pyspv
classes with different altcoins.

requirements
============

pyspv only relies on a small handful of dependencies:

* [Python 3.3](http://www.python.org/) :: It probably works on other versions, but this is my testing platform.
* OpenSSL :: You'll need libssl.so (Linux/Mac) or libeay32.dll (Windows) in your path.
* [Bitarray](https://pypi.python.org/pypi/bitarray/) :: This is required by the bloom filter implementation.

examples
========

You can start by examining the sample applications in the examples directory.

documentation
=============

TODO

Documentation will soon be available at http://docs.pyspv.org/

