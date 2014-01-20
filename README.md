pyspv
=====

pyspv is a no-bullshit easy-to-use Python module implementing the full Bitcoin
SPV client protocol.  Connecting to the Bitcoin network is as easy as:

```python
import pyspv
spv = pyspv.pyspv()
...
```

... but just connecting to the Bitcoin network would be boring.  The real goal
of this project is to make it so you can just ignore all the Bitcoin protocol
details like Blockchain syncing and the peer-to-peer network, and get started
immediately on writing your Bitcoin application.  

I intend to make this Bitcoin client as extensible as possible.  You can
develop a full wallet or just a simple utility to E-mail you when an address
receives coins.  The possibilities are endless.

requirements
============

pyspv only relies on a small handful of dependencies:

* [Python 3.3](http://www.python.org/) :: It probably works on other versions, but this is my testing platform.
* OpenSSL :: You'll need libssl.so (Linux/Mac) or libeay32.dll (Windows) in your path.
* [Bitarray](https://github.com/ilanschnell/bitarray) :: This is required by the bloom filter implementation.

examples
========

You can start by examining the sample applications in the examples directory.

documentation
=============

TODO
