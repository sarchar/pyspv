from . import base58

DEBUG = 0
INFO = 1
WARNING = 2
ERROR = 3
CRITICAL = 4

def bytes_to_hexstring(data, reverse=True):
    if reverse:
        return ''.join(reversed(['{:02x}'.format(v) for v in data]))
    else:
        return ''.join(['{:02x}'.format(v) for v in data])

def hexstring_to_bytes(s, reverse=True):
    if reverse:
        return bytes(reversed([int(s[x:x+2], 16) for x in range(0, len(s), 2)]))
    else:
        return bytes([int(s[x:x+2], 16) for x in range(0, len(s), 2)])

def base58_check(coin, src, version_bytes=0):
    if isinstance(version_bytes, int):
        version_bytes = bytes([version_bytes])

    src = version_bytes + src

    r = coin.hash(src)
    checksum = r[:4]
    s = src + checksum
    
    e = base58.encode(int.from_bytes(s, 'big'))
    if version_bytes == bytes([0]):
        lz = 0
        while lz < len(src) and src[lz] == 0:
            lz += 1

        return ('1' * lz) + e
    return e

def bits_to_target(bits):
    r = bits & 0x007FFFFF
    mant = ( bits >> 24 ) & 0xFF
    neg = -1 if ( bits & 0x00800000 ) != 0 else 1

    if mant <= 3:
        return neg * (r >> (8 * (3 - mant)))
    else:
        return neg * (r << (8 * (mant - 3)))

def target_to_bits(target):
    v = []
    while target != 0:
        v.append(target % 256)
        target //= 256

    if v[-1] > 0x7f:
        v.append(0)

    m = len(v)
    while len(v) < 3:
        v = [0] + v

    return (m << 24) | (v[-1] << 16) | (v[-2] << 8) | v[-3]

