
OP_FALSE     = 0

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

OPCODE_MAP = {
    OP_FALSE         : "OP_FALSE",            
    OP_1             : "OP_1",
    OP_2             : "OP_2",
    OP_3             : "OP_3",
    OP_PUSHDATA1     : "OP_PUSHDATA1",
    OP_PUSHDATA2     : "OP_PUSHDATA2",
    OP_PUSHDATA4     : "OP_PUSHDATA4",
    OP_RETURN        : "OP_RETURN",
    OP_DUP           : "OP_DUP",
    OP_EQUAL         : "OP_EQUAL",
    OP_EQUALVERIFY   : "OP_EQUALVERIFY",
    OP_HASH160       : "OP_HASH160",
    OP_CHECKSIG      : "OP_CHECKSIG",
    OP_CHECKMULTISIG : "OP_CHECKMULTISIG",
}

OPCODE_NAMES = dict((y,x) for x,y in OPCODE_MAP.items())

class Script:
    def __init__(self, program=b''):
        self.program = program

    def push_op(self, op):
        self.program = self.program + bytes([op])

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

