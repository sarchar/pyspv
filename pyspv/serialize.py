import struct
import time

from .bitcoin import Bitcoin

class SerializeDataTooShort(Exception):
    pass

class InvalidNetworkMagic(Exception):
    pass

class InvalidCommandEncoding(Exception):
    pass

class MessageChecksumFailure(Exception):
    pass

class Serialize:
    @staticmethod
    def serialize_variable_int(i):
        if i < 0xfd:
            return struct.pack("B", i)
        if i <= 0xffff:
            return struct.pack("<BH", 0xfd, i)
        if i <= 0xffffffff:
            return struct.pack("<BL", 0xfe, i)
        return struct.pack("<BQ", 0xff, i)

    @staticmethod
    def serialize_variable_int_size(i):
        if i < 0xfd:
            return 1
        if i <= 0xffff:
            return 3
        if i <= 0xffffffff:
            return 5
        return 9

    @staticmethod
    def unserialize_variable_int(data):
        if len(data) == 0:
            raise SerializeDataTooShort()
        i = data[0]
        if i < 0xfd:
            return i, data[1:]
        elif i == 0xfd:
            if len(data) < 3:
                raise SerializeDataTooShort()
            return struct.unpack("<H", data[1:3])[0], data[3:]
        elif i == 0xfe:
            if len(data) < 5:
                raise SerializeDataTooShort()
            return struct.unpack("<L", data[1:5])[0], data[5:]
        else:
            if len(data) < 9:
                raise SerializeDataTooShort()
            return struct.unpack("<Q", data[1:9])[0], data[9:]

    @staticmethod
    def serialize_bytes(b):
        length = Serialize.serialize_variable_int(len(b))
        return length + b

    @staticmethod
    def unserialize_bytes(data):
        length, data = Serialize.unserialize_variable_int(data)
        b = data[:length]
        return b, data[length:]

    @staticmethod
    def serialize_string(s):
        return Serialize.serialize_bytes(s.encode('utf8'))

    @staticmethod
    def unserialize_string(data):
        s, data = Serialize.unserialize_bytes(data)
        return s.decode('utf8'), data

    @staticmethod
    def serialize_object(o):
        if isinstance(o, int):
            return b'v' + Serialize.serialize_variable_int(o)
        elif isinstance(o, bytes):
            return b'b' + Serialize.serialize_bytes(o)
        elif isinstance(o, str):
            return b's' + Serialize.serialize_string(o)
        elif isinstance(o, list):
            return b'l' + Serialize.serialize_list(o)
        elif isinstance(o, dict):
            return b'd' + Serialize.serialize_dict(o)

    @staticmethod
    def unserialize_object(data):
        t = bytes([data[0]])
        if t == b'v':
            return Serialize.unserialize_variable_int(data[1:])
        elif t == b'b':
            return Serialize.unserialize_bytes(data[1:])
        elif t == b's':
            return Serialize.unserialize_string(data[1:])
        elif t == b'l':
            return Serialize.unserialize_list(data[1:])
        elif t == b'd':
            return Serialize.unserialize_dict(data[1:])

    @staticmethod
    def serialize_list(items):
        count = Serialize.serialize_variable_int(len(items))
        r = []
        for item in items:
            r.append(Serialize.serialize_object(item))
        return count + b''.join(r)

    @staticmethod
    def unserialize_list(data):
        count, data = Serialize.unserialize_variable_int(data)
        r = []
        for _ in range(count):
            item, data = Serialize.unserialize_object(data)
            r.append(item)
        return r, data

    @staticmethod
    def serialize_dict(d):
        count = Serialize.serialize_variable_int(len(d.keys()))
        r = []
        for k in d.keys():
            r.append(Serialize.serialize_object(k))
            r.append(Serialize.serialize_object(d[k]))
        return count + b''.join(r)

    @staticmethod
    def unserialize_dict(data):
        count, data = Serialize.unserialize_variable_int(data)
        r = {}
        for _ in range(count):
            k, data = Serialize.unserialize_object(data)
            v, data = Serialize.unserialize_object(data)
            r[k] = v
        return r, data

    @staticmethod
    def serialize_network_address(address, services, with_timestamp=True):
        if address is not None:
            quads   = address[0].split(".")
            address = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, int(quads[0]), int(quads[1]), int(quads[2]), int(quads[3])])
            port    = struct.pack(">H", address[1])
        else:
            address = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0])
            port    = bytes([0, 0])

        if with_timestamp:
            return struct.pack("<LQ", int(time.time()), services) + address + port
        else:
            return struct.pack("<Q", services) + address + port

    @staticmethod
    def unserialize_network_address(data, with_timestamp=True):
        if with_timestamp and len(data) < 30:
            raise MessageTooShort()
        elif not with_timestamp and len(data) < 26:
            raise MessageTooShort()

        if with_timestamp:
            when, services = struct.unpack("<LQ", data[:12])
            data = data[12:]
        else:
            services = struct.unpack("<Q", data[:8])[0]
            data = data[8:]

        address = data[:16]
        port = struct.unpack(">H", data[16:18])[0]

        if address[0:-4] == bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]):
            address = '.'.join('{}'.format(v) for v in address[-4:])

        data = data[18:]

        if with_timestamp:
            return ((address, port), services, when, data)
        else:
            return ((address, port), services, data)

    @staticmethod
    def wrap_network_message(coin, command, payload):
        magic = coin.NETWORK_MAGIC
        command = command[:12].encode("ascii")
        command += bytes([0] * (12 - len(command))) # pad to 12 bytes
        length = struct.pack("<L", len(payload))
        checksum = Bitcoin.hash(payload)[:4] # Checksum is first 4 bytes
        return magic + command + length + checksum + payload

    @staticmethod
    def unwrap_network_message(coin, data):
        '''a message is only complete if the 2nd return value is not None. We return
        command and length so that the network can decide to drop an unresponsive or
        misbehaving peer'''
        if len(data) < 24:
            return None, None, None, data

        magic = data[:4]
        if magic != coin.NETWORK_MAGIC:
            raise InvalidNetworkMagic()

        i = 0
        while data[4+i] != 0 and i < 12:
            i += 1

        try:
            command = data[4:4+i].decode('ascii')
        except UnicodeDecodeError:
            raise InvalidCommandEncoding()

        length = struct.unpack("<L", data[16:20])[0]
        checksum = data[20:24]

        if (len(data) - 24) < length:
            return command, None, length, data
        
        payload = data[24:24+length]
        leftover = data[24+length:]

        hash = Bitcoin.hash(payload)
        if hash[:4] != checksum:
            raise MessageChecksumFailure()

        return command, payload, length, leftover

