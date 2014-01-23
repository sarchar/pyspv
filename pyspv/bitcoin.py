import hashlib

from .util import *

class Bitcoin:
    ADDRESS_VERSION_BYTES     = b'\x00'
    PRIVATE_KEY_VERSION_BYTES = b'\x80'
    NETWORK_MAGIC             = bytes([0xF9, 0xBE, 0xB4, 0xD9]) 

    MAX_BLOCK_SIZE = 1000000

    DEFAULT_PORT = 8333
    
    SEEDS = [
        'seed.bitcoin.sipa.be',
        'dnsseed.bluematt.me',
        'dnsseed.bitcoin.dashjr.org',
        'bitseed.xf2.org',
    ]

    TARGET_BLOCK_TIMESPAN = 14 * 24 * 60 * 60 # Try to adjust POW every two weeks
    TARGET_BLOCK_SPACING  = 10 * 60           # Try to maintain 10 minutes between blocks
    WORK_INTERVAL         = TARGET_BLOCK_TIMESPAN // TARGET_BLOCK_SPACING

    MEDIAN_TIME_SPAN      = 11 # blocks

    COIN = 100000000
    CENT = 1000000
    MAX_COINS = 21000000 * COIN 

    GENESIS_BLOCK_HASH = hexstring_to_bytes("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")

    # Checkpoint block height MUST be a multiple of the work interval in order to verify difficulty changes
    CHECKPOINT_BLOCK_HASH      = hexstring_to_bytes("0000000000000003cbb18a8ea04e14452ad0c3bc92ed709e4df5a50b2a24da0e")
    CHECKPOINT_BLOCK_HEIGHT    = 274176
    CHECKPOINT_BLOCK_TIMESTAMP = 1386684686
    CHECKPOINT_BLOCK_BITS      = 0x1904BA6E

    @staticmethod
    def hash(data):
        hasher = hashlib.sha256()
        hasher.update(data)
        hasher2 = hashlib.sha256()
        hasher2.update(hasher.digest())
        return hasher2.digest()

    @staticmethod
    def hash160(data):
        hasher = hashlib.sha256()
        hasher.update(data)
        hasher2 = hashlib.new('ripemd160')
        hasher2.update(hasher.digest())
        return hasher2.digest()

class BitcoinTestnet(Bitcoin):
    ADDRESS_VERSION_BYTES     = b'\x6f'
    PRIVATE_KEY_VERSION_BYTES = bytes([0x6f + 0x80])
    NETWORK_MAGIC             = bytes([0x0B, 0x11, 0x09, 0x07])

    DEFAULT_PORT = 18333
    
    SEEDS = [
        'testnet-seed.bitcoin.petertodd.org',
        'testnet-seed.bluematt.me',
    ]
 
    GENESIS_BLOCK_HASH = hexstring_to_bytes("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")

    # No checkpoint (yet) for testnet
    CHECKPOINT_BLOCK_HASH      = hexstring_to_bytes("0000000000035aa86364e6659e54913388a6d8d6f42587771a5dc9f9bf383f4f")
    CHECKPOINT_BLOCK_HEIGHT    = 153216
    CHECKPOINT_BLOCK_TIMESTAMP = 1386677918
    CHECKPOINT_BLOCK_BITS      = 0x1B05B143

