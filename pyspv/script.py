import hashlib

from .util import *

OP_FALSE     = 0
OP_0         = 0

OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e

OP_1NEGATE   = 0x4f
OP_RESERVED  = 0x50
OP_1         = 0x51
OP_2         = 0x52
OP_3         = 0x53
OP_4         = 0x54
OP_5         = 0x55
OP_6         = 0x56
OP_7         = 0x57
OP_8         = 0x58
OP_9         = 0x59
OP_10        = 0x5a
OP_11        = 0x5b
OP_12        = 0x5c
OP_13        = 0x5d
OP_14        = 0x5e
OP_15        = 0x5f
OP_16        = 0x60

OP_NOP         = 0x61
OP_VER         = 0x62
OP_IF          = 0x63
OP_NOTIF       = 0x64
OP_VERIF       = 0x65
OP_VERNOTIF    = 0x66
OP_ELSE        = 0x67
OP_ENDIF       = 0x68
OP_VERIFY      = 0x69
OP_RETURN      = 0x6a

OP_TOALTSTACK   = 0x6b
OP_FROMALTSTACK = 0x6c
OP_2DROP        = 0x6d
OP_2DUP         = 0x6e
OP_3DUP         = 0x6f
OP_2OVER        = 0x70
OP_2ROT         = 0x71
OP_2SWAP        = 0x72
OP_IFDUP        = 0x73
OP_DEPTH        = 0x74
OP_DROP         = 0x75
OP_DUP          = 0x76
OP_NIP          = 0x77
OP_OVER         = 0x78
OP_PICK         = 0x79
OP_ROLL         = 0x7a
OP_ROT          = 0x7b
OP_SWAP         = 0x7c
OP_TUCK         = 0x7d

OP_CAT    = 0x7e
OP_SUBSTR = 0x7f
OP_LEFT   = 0x80
OP_RIGHT  = 0x81
OP_SIZE   = 0x82

OP_INVERT      = 0x83
OP_AND         = 0x84
OP_OR          = 0x85
OP_XOR         = 0x86
OP_EQUAL       = 0x87
OP_EQUALVERIFY = 0x88
OP_RESERVED1   = 0x89
OP_RESERVED2   = 0x8a

OP_1ADD      = 0x8b
OP_1SUB      = 0x8c
OP_2MUL      = 0x8d
OP_2DIV      = 0x8e
OP_NEGATE    = 0x8f
OP_ABS       = 0x90
OP_NOT       = 0x91
OP_0NOTEQUAL = 0x92

OP_ADD    = 0x93
OP_SUB    = 0x94
OP_MUL    = 0x95
OP_DIV    = 0x96
OP_MOD    = 0x97
OP_LSHIFT = 0x98
OP_RSHIFT = 0x99

OP_BOOLAND            = 0x9a
OP_BOOLOR             = 0x9b
OP_NUMEQUAL           = 0x9c
OP_NUMEQUALVERIFY     = 0x9d
OP_NUMNOTEQUAL        = 0x9e
OP_LESSTHAN           = 0x9f
OP_GREATERTHAN        = 0xa0
OP_LESSTHANOREQUAL    = 0xa1
OP_GREATERTHANOREQUAL = 0xa2
OP_MIN                = 0xa3
OP_MAX                = 0xa4

OP_WITHIN = 0xa5

OP_RIPEMD160           = 0xa6
OP_SHA1                = 0xa7
OP_SHA256              = 0xa8
OP_HASH160             = 0xa9
OP_HASH256             = 0xaa
OP_CODESEPARATOR       = 0xab
OP_CHECKSIG            = 0xac
OP_CHECKSIGVERIFY      = 0xad
OP_CHECKMULTISIG       = 0xae
OP_CHECKMULTISIGVERIFY = 0xaf

OP_NOP1  = 0xb0
OP_NOP2  = 0xb1
OP_NOP3  = 0xb2
OP_NOP4  = 0xb3
OP_NOP5  = 0xb4
OP_NOP6  = 0xb5
OP_NOP7  = 0xb6
OP_NOP8  = 0xb7
OP_NOP9  = 0xb8
OP_NOP10 = 0xb9

OP_SMALLINTEGER = 0xfa
OP_PUBKEYS      = 0xfb
OP_PUBKEYHASH   = 0xfd
OP_PUBKEY       = 0xfe

OP_INVALIDOPCODE = 0xff

class ScriptFailure(Exception):
    pass

class InvalidScriptElementSize(ScriptFailure):
    pass

class TooManyInstructions(ScriptFailure):
    pass

class DisabledOpcode(ScriptFailure):
    pass

class UnterminatedIfStatement(ScriptFailure):
    pass

class ScriptReturn(ScriptFailure):
    pass

class ScriptVerifyFailure(ScriptFailure):
    pass

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

class ScriptEvaluator:
    CONSTANTS = {
        OP_1NEGATE: b'\xff',
        OP_1      : b'\x01',
        OP_2      : b'\x02',
        OP_3      : b'\x03',
        OP_4      : b'\x04',
        OP_5      : b'\x05',
        OP_6      : b'\x06',
        OP_7      : b'\x07',
        OP_8      : b'\x08',
        OP_9      : b'\x09',
        OP_10     : b'\x0a',
        OP_11     : b'\x0b',
        OP_12     : b'\x0c',
        OP_13     : b'\x0d',
        OP_14     : b'\x0e',
        OP_15     : b'\x0f',
        OP_16     : b'\x10'
    }

    def __init__(self, coin, script):
        self.coin = coin
        self.script = script

    def _get_op(self, pc):
        opcode = self.script.program[pc]
        pc += 1

        data = None
        data_push_size = None
        if opcode < OP_PUSHDATA1:
            data_push_size = opcode
        elif opcode == OP_PUSHDATA1:
            data_push_size = self.script.program[pc]
            pc += 1
        elif opcode == OP_PUSHDATA2:
            data_push_size = self.script.program[pc] | (self.script.program[pc+1] << 8)
            pc += 2
        elif opcode == OP_PUSHDATA4:
            data_push_size = self.script.program[pc] | (self.script.program[pc+1] << 8) | (self.script.program[pc+2] << 16) | (self.script.program[pc+3] << 24)
            pc += 4
         
        if data_push_size is not None:
            data = self.script.program[pc:pc+data_push_size]
            pc += data_push_size
            if len(data) != data_push_size:
                raise IndexError("script too short")

        return opcode, data, pc

    def evaluate(self):
        pc = 0
        opcount = 0
        block_false = 0
        block_exec_values = []
        stack = []
        altstack = []

        def cast_to_bool(b):
            for i, v in enumerate(b):
                if v != 0 and i != (len(b)-1):
                    return True
                elif v != 0x80 and v != 0x00 and i == (len(b)-1):
                    return True
            return False
                    
        def encode_int(v, byte_order='big', signed=True):
            try:
                return v.to_bytes((v.bit_length()+7)//8, byte_order, signed=signed)
            except OverflowError:
                r = v.to_bytes((v.bit_length()+15)//8, byte_order, signed=signed)
                if len(r) > 1 and r[0] == 0 and (r[1] & 0x80) == 0:
                    r = r[1:]
                return r

        while pc < len(self.script.program):
            opcode, data, pc = self._get_op(pc)
            block_exec = (block_false == 0)

            #print("Eval: {} (block_exec={})".format("OP_PUSHDATA1" if opcode < OP_PUSHDATA1 else OPCODE_MAP[opcode], block_exec))

            # Opcodes over OP_16 are non-datapush "do something" opcodes
            if opcode > OP_16:
                opcount += 1
                if opcount > self.coin.MAX_INSTRUCTIONS:
                    raise TooManyInstructions("Script was too long")

            if opcode in self.coin.DISABLED_OPCODES:
                raise DisabledOpcode("Script tried executing and invalid opcode")

            if block_exec and data is not None:
                assert 0 <= opcode <= OP_PUSHDATA4
                if len(data) > self.coin.MAX_SCRIPT_ELEMENT_SIZE:
                    raise InvalidScriptElementSize("Script element was {} bytes".format(len(data)))
                #print("PushData: {}".format(bytes_to_hexstring(data, reverse=False)))
                stack.append(data)

            elif block_exec or (OP_IF <= opcode <= OP_ENDIF):
                if opcode in (OP_NOP, OP_NOP1, OP_NOP2, OP_NOP3, OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10):
                    pass

                elif OP_1NEGATE <= opcode <= OP_16 and opcode != OP_RESERVED:
                    stack.append(ScriptEvaluator.CONSTANTS[opcode])

                elif opcode == OP_IF or opcode == OP_NOTIF:
                    # <expression> if [statements] [else [statements]] endif
                    value = False
                    if block_exec:
                        value = cast_to_bool(stack.pop())
                        if opcode == OP_NOTIF:
                            value = not value
                    if not value:
                        block_false += 1
                    block_exec_values.append(value)

                elif opcode == OP_ELSE:
                    v = block_exec_values[-1]
                    block_exec_values[-1] = not v
                    if v:
                        block_false += 1
                    else:
                        block_false -= 1

                elif opcode == OP_ENDIF:
                    v = block_exec_values.pop()
                    if not v:
                        block_false -= 1

                elif opcode == OP_EQUAL or opcode == OP_EQUALVERIFY:
                    u = stack.pop()
                    v = stack.pop()
                    stack.append(int(u == v).to_bytes(1, 'big'))
                    if opcode == OP_EQUALVERIFY:
                        if cast_to_bool(stack[-1]):
                            stack.pop()
                        else:
                            raise ScriptVerifyFailure()

                elif opcode == OP_VERIFY:
                    v = cast_to_bool(stack.pop())
                    if not v:
                        raise ScriptVerifyFailure()

                elif opcode == OP_RETURN:
                    raise ScriptReturn("Script terminated via OP_RETURN")

                elif opcode == OP_TOALTSTACK:
                    altstack.append(stack.pop())

                elif opcode == OP_FROMALTSTACK:
                    stack.append(altstack.pop())

                elif opcode == OP_2DROP:
                    # (x1 x2 --)
                    stack.pop()
                    stack.pop()

                elif opcode == OP_2DUP:
                    # (x1 x2 -- x1 x2 x1 x2)
                    stack.append(stack[-2])
                    stack.append(stack[-2])


                elif opcode == OP_3DUP:
                    # (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    stack.append(stack[-3])
                    stack.append(stack[-3])
                    stack.append(stack[-3])

                elif opcode == OP_2OVER:
                    # (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    stack.append(stack[-4])
                    stack.append(stack[-4])

                elif opcode == OP_2ROT:
                    # (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    x1, x2, stack = stack[-6], stack[-5], stack[:-6] + stack[-4:]
                    stack.append(x1)
                    stack.append(x2)

                elif opcode == OP_2SWAP:
                    # (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    stack[-4], stack[-3], stack[-2], stack[-1] = stack[-2], stack[-1], stack[-4], stack[-3]

                elif opcode == OP_IFDUP:
                    # (x -- x or x -- x x)
                    v = stack[-1]
                    if cast_to_bool(v):
                        stack.append(v)
                
                elif opcode == OP_DEPTH:
                    # (x .. -- x .. xD) where D is len(stack)
                    stack.append(encode_int(len(stack)))

                elif opcode == OP_DROP:
                    # (x --)
                    stack.pop()

                elif opcode == OP_DUP:
                    # (x -- x x)
                    stack.append(stack[-1])

                elif opcode == OP_NIP:
                    # (x1 x2 -- x2)
                    stack[-2] = stack[-1]
                    stack.pop()

                elif opcode == OP_OVER:
                    # (x1 x2 -- x1 x2 x1)
                    stack.append(stack[-2])

                elif opcode in (OP_PICK, OP_ROLL):
                    # OP_PICK: (xn ... x2 x1 x0 n -- xn ... x2 x1 x0 xn)
                    # OP_ROLL: (xn ... x2 x1 x0 n -- ... x2 x1 x0 xn)
                    v = int.from_bytes(stack.pop(), 'big')
                    stack = stack[:-v-1] + ([stack[-v-1]] if opcode == OP_PICK else []) + (stack[-v:] if v > 0 else []) + [stack[-v-1]]

                elif opcode == OP_ROT:
                    # (x1 x2 x3 -- x2 x3 x1)
                    stack[-3], stack[-2], stack[-1] = stack[-2], stack[-1], stack[-3]

                elif opcode == OP_SWAP:
                    # (x1 x2 -- x2 x1)
                    stack[-2], stack[-1] = stack[-1], stack[-2]

                elif opcode == OP_TUCK:
                    # (x1 x2 -- x2 x1 x2)
                    a = stack.pop()
                    b = stack.pop()
                    stack += [a, b, a]
                
                elif opcode == OP_SIZE:
                    # (x -- x len(x))
                    stack.append(encode_int(len(stack[-1])))

                elif opcode in (OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL):
                    # (in -- out)
                    v = int.from_bytes(stack.pop(), 'big', signed=True)
                    if   opcode == OP_1ADD:      v += 1
                    elif opcode == OP_1SUB:      v -= 1
                    elif opcode == OP_NEGATE:    v = -v
                    elif opcode == OP_ABS:       v = -v if v < 0 else v
                    elif opcode == OP_NOT:       v = (v == 0)
                    elif opcode == OP_0NOTEQUAL: v = (v != 0)
                    stack.append(encode_int(v))

                elif opcode in (OP_ADD, OP_SUB, OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHAN, OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX):
                    # (x1 x2 -- out)
                    x2 = int.from_bytes(stack.pop(), 'big', signed=True)
                    x1 = int.from_bytes(stack.pop(), 'big', signed=True)
                    v = None
                    if   opcode == OP_ADD:                v = x1 + x2
                    elif opcode == OP_SUB:                v = x1 - x2
                    elif opcode == OP_BOOLAND:            v = (x1 != 0 and x2 != 0)
                    elif opcode == OP_BOOLOR:             v = (x1 != 0 or x2 != 0)
                    elif opcode == OP_NUMEQUAL:           v = (x1 == x2)
                    elif opcode == OP_NUMEQUALVERIFY:     v = (x1 == x2)
                    elif opcode == OP_NUMNOTEQUAL:        v = (x1 != x2)
                    elif opcode == OP_LESSTHAN:           v = (x1 < x2)
                    elif opcode == OP_LESSTHANOREQUAL:    v = (x1 <= x2)
                    elif opcode == OP_GREATERTHAN:        v = (x1 > x2)
                    elif opcode == OP_GREATERTHANOREQUAL: v = (x1 >= x2)
                    elif opcode == OP_MIN:                v = min(x1, x2)
                    elif opcode == OP_MAX:                v = max(x1, x2)
                    stack.append(encode_int(v))

                    if opcode == OP_NUMEQUALVERIFY:
                        if cast_to_bool(stack[-1]):
                            stack.pop()
                        else:
                            raise ScriptVerifyFailure()

                elif opcode == OP_WITHIN:
                    # (x min max -- out)
                    b = int.from_bytes(stack.pop(), 'big', signed=True)
                    a = int.from_bytes(stack.pop(), 'big', signed=True)
                    x = int.from_bytes(stack.pop(), 'big', signed=True)
                    stack.append(encode_int(int(a <= x < b)))

                elif opcode == OP_RIPEMD160:
                    data = stack.pop()
                    hasher = hashlib.new('ripemd160')
                    hasher.update(data)
                    stack.append(hasher.digest())

                elif opcode == OP_SHA1:
                    data = stack.pop()
                    hasher = hashlib.sha1()
                    hasher.update(data)
                    stack.append(hasher.digest())

                elif opcode == OP_SHA256:
                    data = stack.pop()
                    hasher = hashlib.sha256()
                    hasher.update(data)
                    stack.append(hasher.digest())

                elif opcode == OP_HASH160:
                    data = stack.pop()
                    hasher = hashlib.sha256()
                    hasher.update(data)
                    hasher2 = hashlib.new('ripemd160')
                    hasher2.update(hasher.digest())
                    stack.append(hasher2.digest())

                elif opcode == OP_HASH256:
                    data = stack.pop()
                    hasher = hashlib.sha256()
                    hasher.update(data)
                    hasher2 = hashlib.sha256()
                    hasher2.update(hasher.digest())
                    stack.append(hasher2.digest())

        if len(block_exec_values):
            raise UnterminatedIfStatement("Program didn't close {} IF statements".format(len(block_exec_values)))

        return stack


