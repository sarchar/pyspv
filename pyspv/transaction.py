import struct

from .script import Script
from .serialize import Serialize
from .util import *

class TransactionOutput:
    def __init__(self, amount=0, script=Script()):
        self.amount = amount
        self.script = script

    def serialize(self):
        data_list = []

        data_list.append(struct.pack("<Q", self.amount))
        script_bytes = self.script.serialize()
        data_list.append(Serialize.serialize_variable_int(len(script_bytes)))
        data_list.append(script_bytes)

        return b''.join(data_list)

    def serialize_size(self):
        data_size = 8

        script_size = self.script.serialize_size()

        data_size += Serialize.serialize_variable_int_size(script_size)
        data_size += script_size

        return data_size

    @staticmethod
    def unserialize(data):
        amount = struct.unpack("<Q", data[:8])[0]
        script_size, data = Serialize.unserialize_variable_int(data[8:])
        script = data[:script_size] #Script.unserialize(data, script_size)

        tx_output = TransactionOutput(amount=amount, script=Script(script))
        return tx_output, data[script_size:]

    def __str__(self):
        return '<tx_output amount={} script={} bytes>'.format(self.amount, len(self.script.program))

class TransactionPrevOut:
    def __init__(self, tx_hash=None, n=0):
        self.tx_hash = tx_hash
        self.n = n

    def serialize(self):
        return self.tx_hash + struct.pack("<L", self.n)

    def serialize_size(self):
        return 32 + 4

    @staticmethod
    def unserialize(data):
        tx_hash = data[:32]
        n = struct.unpack("<L", data[32:36])[0]
        return TransactionPrevOut(tx_hash, n), data[36:]

class TransactionInput:
    def __init__(self, prevout=TransactionPrevOut(), script=Script(), sequence=0xffffffff):
        self.prevout = prevout
        self.script = script
        self.sequence = sequence

    def is_final(self):
        return self.sequence == 0xffffffff

    def serialize(self):
        data_list = []
        data_list.append(self.prevout.serialize())

        script_bytes = self.script.serialize()
        data_list.append(Serialize.serialize_variable_int(len(script_bytes)))
        data_list.append(script_bytes)

        data_list.append(struct.pack("<L", self.sequence))

        return b''.join(data_list)

    def serialize_size(self):
        data_size = 0
        data_size += self.prevout.serialize_size()

        script_size = self.script.serialize_size()
        data_size += Serialize.serialize_variable_int_size(script_size)
        data_size += script_size

        data_size += 4
        return data_size

    @staticmethod
    def unserialize(data):
        prevout, data = TransactionPrevOut.unserialize(data)

        script_size, data = Serialize.unserialize_variable_int(data)
        script = data[:script_size] #Script.unserialize(data, script_size, as_coinbase=as_coinbase)
        sequence = struct.unpack("<L", data[script_size:script_size+4])[0]

        tx_input = TransactionInput(prevout=prevout, script=Script(script), sequence=sequence)
        return tx_input, data[script_size+4:]

    def __str__(self):
        return '<tx_input {}:{} sequence={:04x} script={} bytes>'.format(bytes_to_hexstring(self.prevout.tx_hash), self.prevout.n, self.sequence, len(self.script.program))

class Transaction:
    CURRENT_VERSION = 1

    def __init__(self, coin, version=CURRENT_VERSION, inputs=None, outputs=None, lock_time=0):
        self.coin = coin
        self.version = version
        self.inputs = [] if inputs is None else inputs
        self.outputs = [] if outputs is None else outputs
        self.lock_time = lock_time

    def __hash__(self):
        return self.hash()

    def hash(self):
        return self.coin.hash(self.serialize())

    def is_coinbase(self):
        return len(self.inputs) == 1 and self.inputs[0].prevout.tx_hash == (b'\x00' * 32) and self.inputs[0].prevout.n == 0xffffffff

    def is_final(self, height, block_time):
        if self.lock_time == 0:
            return True

        k = height if self.lock_time < 500000000 else block_time
        if self.lock_time < k:
            return True

        if not all(txin.is_final() for txin in self.inputs):
            return False

        return True

    def serialize(self):
        data_list = []
        data_list.append(struct.pack("<L", self.version))

        data_list.append(Serialize.serialize_variable_int(len(self.inputs)))
        for i, input in enumerate(self.inputs):
            data_list.append(input.serialize())

        data_list.append(Serialize.serialize_variable_int(len(self.outputs)))
        for i, output in enumerate(self.outputs):
            data_list.append(output.serialize())

        data_list.append(struct.pack("<L", self.lock_time))

        return b''.join(data_list)

    def serialize_size(self):
        data_size = 0
        data_size += 4

        data_size += Serialize.serialize_variable_int_size(len(self.inputs))
        for i, input in enumerate(self.inputs):
            data_size += input.serialize_size()

        data_size += Serialize.serialize_variable_int_size(len(self.outputs))
        for i, output in enumerate(self.outputs):
            data_size += output.serialize_size()

        data_size += 4
        return data_size
 
    @staticmethod
    def unserialize(data, coin):
        version = struct.unpack('<L', data[:4])[0]

        inputs = []
        num_inputs, data = Serialize.unserialize_variable_int(data[4:])
        for i in range(num_inputs):
            tx_input, data = TransactionInput.unserialize(data)
            inputs.append(tx_input)

        outputs = []
        num_outputs, data = Serialize.unserialize_variable_int(data)
        for i in range(num_outputs):
            tx_output, data = TransactionOutput.unserialize(data)
            outputs.append(tx_output)

        lock_time = struct.unpack("<L", data[:4])[0]

        tx = Transaction(coin, version=version, inputs=inputs, outputs=outputs, lock_time=lock_time)
        return tx, data[4:]
 
    def __str__(self):
        s = '<tx {}\n\t{}\n\t{}\n\tlock_time={}>'.format(bytes_to_hexstring(self.hash()), 
                '\n\t'.join('input: {}'.format(str(i)) for i in self.inputs),
                '\n\t'.join('output: {}'.format(str(o)) for o in self.outputs),
                self.lock_time)
        return s

def test():
    from .bitcoin import Bitcoin
    data = hexstring_to_bytes('0100000001739E3D5B0883D1D0ADAD5ED86A5A18E34F596CB0CAE8F2D8AA187B538D0A39EC000000008B48304502206DA82264895FA57D5677EB61F792896636FFBF006B77DBFBBAF0212D2BAF18A102210080568509E0FBBCE28CBA9DBBDAFE997222F041D37942814E60979711ACB46355014104529D7C2AE7FFE0672B68690E0A58558EA644FB54DF2D15C24CC26347C9939D276A0C0F26031F7575D1F85C5DCF0ED5602242905050201EADF1997E12369BE0B1FFFFFFFF0290B6AE00000000001976A914BC4AB5E05CE0F81BC149CD2F9F4091B66BFE8C0388AC40420F00000000001976A91406F1B66FB6C0E253F24C74D3ED972FF447CA285C88AC00000000', reverse=False)
    tx, r = Transaction.unserialize(data, Bitcoin)
    assert len(r) == 0
    print(str(tx))

#test()
