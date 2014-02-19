import hashlib
import string

from .util import *

class InvalidMoney(Exception):
    pass

class Bitcoin:
    NAME                       = 'Bitcoin'

    ADDRESS_VERSION_BYTES      = b'\x00'
    ADDRESS_BYTE_LENGTH        = 25 # 1 for version byte + 20 for ripemd60 hash + 4 for checksum
    P2SH_ADDRESS_VERSION_BYTES = b'\x05'
    P2SH_ADDRESS_BYTE_LENGTH   = 25 # 1 for version byte + 20 for ripemd60 hash + 4 for checksum
    PRIVATE_KEY_VERSION_BYTES  = b'\x80'
    NETWORK_MAGIC              = bytes([0xF9, 0xBE, 0xB4, 0xD9]) 

    TRANSACTION_VERSION = 1

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
    DUST_LIMIT = 100000

    MAXIMUM_TRANSACTION_FEE = 1000000
    MINIMUM_TRANSACTION_FEE = 10000
    MINIMUM_TRANSACTION_FEE_FOR_RELAY = 10000

    # Number of confirmations for a transaction to be considered confirmed
    TRANSACTION_CONFIRMATION_DEPTH = 7

    # Genesis details
    GENESIS_BLOCK_HASH      = hexstring_to_bytes("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
    GENESIS_BLOCK_TIMESTAMP = 1231006505
    GENESIS_BLOCK_BITS      = 0x1D00FFFF

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

    @staticmethod
    def format_money(amount):
        assert isinstance(amount, int)
        neg = ''
        if amount < 0:
            neg = '-'
            amount *= -1
        dec = amount % 100000000
        v = '{}{}.{:08}'.format(neg, amount // 100000000, dec).rstrip('0')
        if v[-1] == '.':
            v = v + '0'
        return v


    @staticmethod
    def parse_money(s):
        '''convert money in the form of a string to int in satoshis'''
        if ',' in s:
            raise InvalidMoney("no commas allowed")

        s = s.strip()

        # If the number starts with a '-' we need to remember that
        neg = 1
        if len(s) and s[0] == '-':
            neg = -1
            s = s[1:]

        # The rest of the number can only be 0..9 and a period
        assert len(set(s).difference(set(string.digits + "."))) == 0

        # Handle case when zero or empty string is passed in
        s = s.strip()
        if len(s) == 0: 
            raise InvalidMoney("empty string")

        s = s.lstrip('0')
        if len(s) == 0:
            return 0

        # Find the first '.', and if there are more then int() will raise a ValueError
        i = s.find('.')
        scale = 100000000

        if i < 0:
            # No '.' found, use it as a whole number
            v = int(s) * scale
        elif i == len(s) - 1:
            # The '.' was the last char in the string, ignore it
            s = s[:-1]
            if len(s) == 0:
                v = 0
            else:
                v = int(s) * scale
        else:
            # Cannot pass two decimals
            dec = s[i+1:].rstrip('0')
            assert '.' not in dec

            num_dec = len(dec)  # number of decimals present (trailing 0s have already been removed)
            scale = scale // (10 ** num_dec)
            s = s[:i] + dec
            if len(s) == 0:
                v = 0
            else:
                v = int(s) * scale

        return neg * v


class BitcoinTestnet(Bitcoin):
    ADDRESS_VERSION_BYTES      = b'\x6f'
    P2SH_ADDRESS_VERSION_BYTES = bytes([196])
    PRIVATE_KEY_VERSION_BYTES  = bytes([0x6f + 0x80])
    NETWORK_MAGIC              = bytes([0x0B, 0x11, 0x09, 0x07])

    DEFAULT_PORT = 18333
    
    SEEDS = [
        'testnet-seed.bitcoin.petertodd.org',
        'testnet-seed.bluematt.me',
    ]
 
    GENESIS_BLOCK_HASH      = hexstring_to_bytes("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
    GENESIS_BLOCK_TIMESTAMP = 1296688602
    GENESIS_BLOCK_BITS      = 0x1D00FFFF

    # No checkpoint (yet) for testnet
    CHECKPOINT_BLOCK_HASH      = hexstring_to_bytes("0000000000035aa86364e6659e54913388a6d8d6f42587771a5dc9f9bf383f4f")
    CHECKPOINT_BLOCK_HEIGHT    = 153216
    CHECKPOINT_BLOCK_TIMESTAMP = 1386677918
    CHECKPOINT_BLOCK_BITS      = 0x1B05B143

Bitcoin.Testnet = BitcoinTestnet

