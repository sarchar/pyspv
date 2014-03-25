
OP_FALSE     = 0
OP_0         = 0

OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e

OP_1         = 0x51
OP_2         = 0x52
OP_3         = 0x53

OP_RETURN      = 0x6a

OP_DUP           = 0x76
OP_EQUAL         = 0x87
OP_EQUALVERIFY   = 0x88
OP_HASH160       = 0xa9
OP_CHECKMULTISIG = 0xae
OP_CHECKSIG      = 0xac

OPCODE_MAP = {}
OPCODE_NAMES = {}

for name in list(globals().keys()):
    if name.startswith('OP_'):
        v = globals()[name]
        if isinstance(v, int) and 0 <= v <= 0xff:
            OPCODE_MAP[v] = name
            OPCODE_NAMES[name] = v

class Script:
    def __init__(self, program=b''):
        self.program = program

    def push_op(self, op):
        self.program = self.program + bytes([op])

    def push_int(self, v):
        if v == 0:
            self.program = self.program + bytes([0])
        elif v >= 1 and v <= 16:
            self.program = self.program + bytes([v + 80])
        else:
            raise Exception("invalid int")

    def push_bytes(self, data):
        assert isinstance(data, bytes)

        if len(data) < int(OP_PUSHDATA1):
            self.program = self.program + bytes([len(data)])
        elif len(data) <= 0xff:
            self.program = self.program + bytes([OP_PUSHDATA1, len(data)])
        elif len(data) <= 0xffff:
            self.program = self.program + bytes([OP_PUSHDATA2, len(data) & 0xff, (len(data) >> 8) & 0xff])
        else:
            self.program = self.program + bytes([OP_PUSHDATA4, len(data) & 0xff, (len(data) >> 8) & 0xff, (len(data) >> 16) & 0xff, (len(data) >> 24) & 0xff])
        
        self.program = self.program + data

    def serialize(self):
        return self.program

    def serialize_size(self):
        return len(self.program)

