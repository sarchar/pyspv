import unittest

from pyspv import Bitcoin
from pyspv.script import *

class TestDataPushes(unittest.TestCase):
    def test_pushdata1_1(self):
        script = Script()
        script.push_bytes(b'\x00')
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x00'])

    def test_pushdata1_2(self):
        msg = b'Hello, world!'
        script = Script()
        script.push_bytes(b'\x00')
        script.push_bytes(msg)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x00', msg])

    def test_pushdata2_1(self):
        msg = b'\x00' * 257
        script = Script()
        script.push_bytes(msg)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [msg])

    def test_pushdata4_1(self):
        msg = b'\x00' * 0x01000000
        script = Script()
        script.push_bytes(msg)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(InvalidScriptElementSize, evaluator.evaluate)

class TestInvalidOpcodes(unittest.TestCase):
    def test1(self):
        for op in Bitcoin.DISABLED_OPCODES:
            script = Script()
            script.push_op(op)
            evaluator = ScriptEvaluator(Bitcoin, script)
            self.assertRaises(DisabledOpcode, evaluator.evaluate)

class TestTooManyInstructions(unittest.TestCase):
    def test1(self):
        script = Script()
        for _ in range(Bitcoin.MAX_INSTRUCTIONS+1):
            script.push_op(OP_NOP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(TooManyInstructions, evaluator.evaluate)

class TestIf(unittest.TestCase):
    def test1(self):
        script = Script()
        script.push_bytes(b'\x01')
        script.push_op(OP_IF)
        script.push_bytes(b'\x03')
        script.push_op(OP_ELSE)
        script.push_bytes(b'\x02')
        script.push_op(OP_ENDIF)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x03'])

    def test2(self):
        script = Script()
        script.push_bytes(b'\x00')
        script.push_op(OP_IF)
        script.push_bytes(b'\x03')
        script.push_op(OP_ELSE)
        script.push_bytes(b'\x02')
        script.push_op(OP_ENDIF)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x02'])

    def test3(self):
        script = Script()
        script.push_bytes(b'\x00')
        script.push_op(OP_IF)
        script.push_bytes(b'\x02')
        script.push_op(OP_ENDIF)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [])

    def test4(self):
        script = Script()
        script.push_bytes(b'\x00\x80')
        script.push_op(OP_NOTIF)
        script.push_bytes(b'\x03')
        script.push_op(OP_ENDIF)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x03'])

    def test5(self):
        script = Script()
        script.push_bytes(b'\x70')
        script.push_op(OP_IF)
        script.push_bytes(b'\x03')
        script.push_op(OP_ENDIF)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x03'])

    def test6(self):
        script = Script()
        script.push_bytes(b'\x70')
        script.push_op(OP_IF)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(UnterminatedIfStatement, evaluator.evaluate)

    def test7(self):
        script = Script()
        script.push_op(OP_ENDIF)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test8(self):
        script = Script()
        script.push_op(OP_ELSE)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test9(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_IF)
        script.push_op(OP_3)
        script.push_op(OP_ENDIF)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x03'])

class TestConstants(unittest.TestCase):
    def test1(self):
        for op in range(OP_1NEGATE, OP_16+1):
            if op == OP_RESERVED:
                self.assertFalse(op in ScriptEvaluator.CONSTANTS)
                continue
            else:
                self.assertTrue(op in ScriptEvaluator.CONSTANTS)

            script = Script()
            script.push_op(op)
            evaluator = ScriptEvaluator(Bitcoin, script)
            stack = evaluator.evaluate()
            self.assertEqual(stack, [ScriptEvaluator.CONSTANTS[op]])

    def test2(self):
        script = Script()
        script.push_op(OP_FALSE)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b''])

class TestNops(unittest.TestCase):
    def test1(self):
        for op in (OP_NOP, OP_NOP1, OP_NOP2, OP_NOP3, OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10):
            script = Script()
            script.push_op(OP_1)
            script.push_op(op)
            script.push_op(OP_2)
            evaluator = ScriptEvaluator(Bitcoin, script)
            stack = evaluator.evaluate()
            self.assertEqual(stack, [b'\x01', b'\x02'])

class TestOther(unittest.TestCase):
    def test_return1(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_RETURN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(ScriptReturn, evaluator.evaluate)

    def test_verify1(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_VERIFY)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [])

    def test_verify2(self):
        script = Script()
        script.push_op(OP_0)
        script.push_op(OP_VERIFY)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(ScriptVerifyFailure, evaluator.evaluate)

class TestEqual(unittest.TestCase):
    def test1(self):
        script = Script()
        script.push_op(OP_2)
        script.push_bytes(b'\x02')
        script.push_op(OP_EQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01'])

    def test2(self):
        script = Script()
        script.push_op(OP_3)
        script.push_bytes(b'\x02')
        script.push_op(OP_EQUALVERIFY)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(ScriptVerifyFailure, evaluator.evaluate)

    def test3(self):
        script = Script()
        script.push_op(OP_3)
        script.push_bytes(b'\x02')
        script.push_op(OP_EQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x00'])

class TestAltStack(unittest.TestCase):
    def test1(self):
        script = Script()
        script.push_op(OP_FROMALTSTACK)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test2(self):
        script = Script()
        script.push_op(OP_TOALTSTACK)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test3(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_TOALTSTACK)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [])

    def test4(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_TOALTSTACK)
        script.push_op(OP_FROMALTSTACK)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x05'])

class TestStackOps(unittest.TestCase):
    def test1(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_2DROP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test2(self):
        script = Script()
        script.push_op(OP_2DROP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test3(self):
        script = Script()
        script.push_op(OP_1)
        script.push_bytes(b'\xff\xff')
        script.push_op(OP_2DROP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [])

    def test4(self):
        script = Script()
        script.push_bytes(b'\x01')
        script.push_bytes(b'\x02')
        script.push_op(OP_2DUP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'\x02', b'\x01', b'\x02'])

    def test5(self):
        script = Script()
        script.push_bytes(b'\x01')
        script.push_op(OP_2DUP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test6(self):
        script = Script()
        script.push_bytes(b'\x01')
        script.push_bytes(b'\x02')
        script.push_bytes(b'\x03')
        script.push_op(OP_3DUP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'\x02', b'\x03', b'\x01', b'\x02', b'\x03'])

    def test7(self):
        script = Script()
        script.push_bytes(b'\x01')
        script.push_op(OP_3DUP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test8(self):
        script = Script()
        script.push_bytes(b'\x01')
        script.push_bytes(b'\x02')
        script.push_op(OP_3DUP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test9(self):
        script = Script()
        script.push_bytes(b'\x01')
        script.push_bytes(b'\x02')
        script.push_bytes(b'\x03')
        script.push_bytes(b'\x04')
        script.push_op(OP_2OVER)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'\x02', b'\x03', b'\x04', b'\x01', b'\x02'])

    def test10(self):
        for i in range(1, 4):
            script = Script()
            for j in range(1, i+1):
                script.push_bytes(bytes([j]))
            script.push_op(OP_2OVER)
            evaluator = ScriptEvaluator(Bitcoin, script)
            self.assertRaises(IndexError, evaluator.evaluate)

    def test11(self):
        script = Script()
        script.push_bytes(b'\x01')
        script.push_bytes(b'\x02')
        script.push_bytes(b'\x03')
        script.push_bytes(b'\x04')
        script.push_bytes(b'\x05')
        script.push_bytes(b'\x06')
        script.push_op(OP_2ROT)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x03', b'\x04', b'\x05', b'\x06', b'\x01', b'\x02'])

    def test12(self):
        for i in range(1, 6):
            script = Script()
            for j in range(1, i+1):
                script.push_bytes(bytes([j]))
            script.push_op(OP_2ROT)
            evaluator = ScriptEvaluator(Bitcoin, script)
            self.assertRaises(IndexError, evaluator.evaluate)

    def test13(self):
        script = Script()
        script.push_bytes(b'\x01')
        script.push_bytes(b'\x02')
        script.push_bytes(b'\x03')
        script.push_bytes(b'\x04')
        script.push_op(OP_2SWAP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x03', b'\x04', b'\x01', b'\x02'])

    def test14(self):
        for i in range(1, 4):
            script = Script()
            for j in range(1, i+1):
                script.push_bytes(bytes([j]))
            script.push_op(OP_2SWAP)
            evaluator = ScriptEvaluator(Bitcoin, script)
            self.assertRaises(IndexError, evaluator.evaluate)

    def test15(self):
        script = Script()
        script.push_bytes(b'\x01')
        script.push_op(OP_IFDUP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'\x01'])

    def test16(self):
        script = Script()
        script.push_bytes(b'\x00')
        script.push_op(OP_IFDUP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x00'])

    def test17(self):
        script = Script()
        script.push_bytes(b'\x00')
        script.push_op(OP_IFDUP)
        script.push_bytes(b'\x01')
        script.push_op(OP_IFDUP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x00', b'\x01', b'\x01'])

    def test18(self):
        script = Script()
        script.push_op(OP_IFDUP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test19(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_DEPTH)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'\x01'])

    def test20(self):
        for i in range(1, 128):
            script = Script()
            for _ in range(i):
                script.push_op(OP_1)
            script.push_op(OP_DEPTH)
            evaluator = ScriptEvaluator(Bitcoin, script)
            stack = evaluator.evaluate()
            self.assertEqual(stack, [b'\x01'] * i + [i.to_bytes(1, 'big', signed=True)])
    
    def test21(self):
        for i in range(128, 512):
            script = Script()
            for _ in range(i):
                script.push_op(OP_1)
            script.push_op(OP_DEPTH)
            evaluator = ScriptEvaluator(Bitcoin, script)
            stack = evaluator.evaluate()
            self.assertEqual(stack, [b'\x01'] * i + [i.to_bytes(2, 'big', signed=True)])

    def test22(self):
        script = Script()
        script.push_op(OP_DEPTH)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b''])

    def test23(self):
        script = Script()
        script.push_op(OP_DROP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test24(self):
        script = Script()
        script.push_op(OP_3)
        script.push_op(OP_DROP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [])

    def test25(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_3)
        script.push_op(OP_DROP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01'])

    def test26(self):
        script = Script()
        script.push_op(OP_3)
        script.push_op(OP_DUP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x03', b'\x03'])

    def test27(self):
        script = Script()
        script.push_op(OP_DUP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test28(self):
        script = Script()
        script.push_op(OP_2)
        script.push_op(OP_1)
        script.push_op(OP_DUP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x02', b'\x01', b'\x01'])

    def test29(self):
        script = Script()
        script.push_op(OP_2)
        script.push_op(OP_1)
        script.push_op(OP_NIP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01'])

    def test30(self):
        script = Script()
        script.push_op(OP_3)
        script.push_op(OP_2)
        script.push_op(OP_1)
        script.push_op(OP_NIP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x03', b'\x01'])

    def test31(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_NIP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test32(self):
        script = Script()
        script.push_op(OP_NIP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test33(self):
        script = Script()
        script.push_op(OP_OVER)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test34(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_OVER)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test35(self):
        script = Script()
        script.push_op(OP_3)
        script.push_op(OP_1)
        script.push_op(OP_OVER)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x03', b'\x01', b'\x03'])

    def test36(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_0)
        script.push_op(OP_PICK)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'\x01'])

    def test37(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_2)
        script.push_op(OP_3)
        script.push_op(OP_4)
        script.push_op(OP_0)
        script.push_op(OP_PICK)
        script.push_op(OP_4)
        script.push_op(OP_PICK)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'\x02', b'\x03', b'\x04', b'\x04', b'\x01'])

    def test38(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_2)
        script.push_op(OP_2)
        script.push_op(OP_PICK)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test39(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_0)
        script.push_op(OP_ROLL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01'])

    def test40(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_2)
        script.push_op(OP_3)
        script.push_op(OP_4)
        script.push_op(OP_0)
        script.push_op(OP_ROLL)
        script.push_op(OP_2)
        script.push_op(OP_ROLL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'\x03', b'\x04', b'\x02'])

    def test41(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_2)
        script.push_op(OP_2)
        script.push_op(OP_ROLL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test42(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_6)
        script.push_op(OP_7)
        script.push_op(OP_ROT)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x06', b'\x07', b'\x05'])

    def test43(self):
        script = Script()
        script.push_op(OP_6)
        script.push_op(OP_7)
        script.push_op(OP_ROT)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test44(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_ROT)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test45(self):
        script = Script()
        script.push_op(OP_6)
        script.push_op(OP_7)
        script.push_op(OP_SWAP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x07', b'\x06'])

    def test46(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_SWAP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test47(self):
        script = Script()
        script.push_op(OP_6)
        script.push_op(OP_7)
        script.push_op(OP_SWAP)
        script.push_op(OP_SWAP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x06', b'\x07'])

    def test48(self):
        script = Script()
        script.push_op(OP_6)
        script.push_op(OP_7)
        script.push_op(OP_TUCK)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x07', b'\x06', b'\x07'])

    def test49(self):
        script = Script()
        script.push_op(OP_6)
        script.push_op(OP_7)
        script.push_op(OP_TUCK)
        script.push_op(OP_SWAP)
        script.push_op(OP_TUCK)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x07', b'\x06', b'\x07', b'\x06'])

    def test50(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_TUCK)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test51(self):
        for j in range(128):
            script = Script()
            script.push_bytes(bytes([1] * j))
            script.push_op(OP_SIZE)
            script.push_op(OP_SWAP)
            script.push_op(OP_DROP)
            evaluator = ScriptEvaluator(Bitcoin, script)
            stack = evaluator.evaluate()
            self.assertEqual(stack, [bytes([j]) if j != 0 else b''])

    def test52(self):
        script = Script()
        script.push_op(OP_SIZE)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

class TestUnaryOps(unittest.TestCase):
    def test1(self):
        script = Script()
        script.push_op(OP_0)
        script.push_op(OP_1ADD)
        script.push_op(OP_7)
        script.push_op(OP_1ADD)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'\x08'])

    def test2(self):
        script = Script()
        script.push_op(OP_1ADD)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test3(self):
        script = Script()
        script.push_op(OP_0)
        script.push_op(OP_1SUB)
        script.push_op(OP_7)
        script.push_op(OP_1SUB)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\xff', b'\x06'])

    def test4(self):
        script = Script()
        script.push_op(OP_1SUB)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test5(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_NEGATE)
        script.push_op(OP_0)
        script.push_op(OP_1SUB)
        script.push_op(OP_NEGATE)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\xff', b'\x01'])

    def test6(self):
        script = Script()
        script.push_op(OP_NEGATE)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test7(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_NEGATE)
        script.push_op(OP_ABS)
        script.push_op(OP_0)
        script.push_op(OP_1ADD)
        script.push_op(OP_ABS)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'\x01'])

    def test8(self):
        script = Script()
        script.push_op(OP_ABS)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test9(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_NOT)
        script.push_op(OP_0)
        script.push_op(OP_NOT)
        script.push_op(OP_7)
        script.push_op(OP_NOT)
        script.push_op(OP_NOT)
        script.push_op(OP_0)
        script.push_op(OP_NOT)
        script.push_op(OP_NOT)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'', b'\x01', b'\x01', b''])

    def test10(self):
        script = Script()
        script.push_op(OP_NOT)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test11(self):
        script = Script()
        script.push_op(OP_1)
        script.push_op(OP_0NOTEQUAL)
        script.push_op(OP_0)
        script.push_op(OP_0NOTEQUAL)
        script.push_op(OP_7)
        script.push_op(OP_0NOTEQUAL)
        script.push_op(OP_0NOTEQUAL)
        script.push_op(OP_0)
        script.push_op(OP_0NOTEQUAL)
        script.push_op(OP_0NOTEQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'', b'\x01', b''])

    def test12(self):
        script = Script()
        script.push_op(OP_0NOTEQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test13(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_ADD)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x0c'])

    def test14(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_ADD)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test15(self):
        script = Script()
        script.push_op(OP_ADD)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test16(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_SUB)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\xfe'])

    def test17(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_SUB)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test18(self):
        script = Script()
        script.push_op(OP_SUB)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test19(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_BOOLAND)
        script.push_op(OP_0)
        script.push_op(OP_7)
        script.push_op(OP_BOOLAND)
        script.push_op(OP_7)
        script.push_op(OP_0)
        script.push_op(OP_BOOLAND)
        script.push_op(OP_0)
        script.push_op(OP_0)
        script.push_op(OP_BOOLAND)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'', b'', b''])

    def test20(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_BOOLAND)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test21(self):
        script = Script()
        script.push_op(OP_BOOLAND)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test22(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_BOOLOR)
        script.push_op(OP_0)
        script.push_op(OP_7)
        script.push_op(OP_BOOLOR)
        script.push_op(OP_7)
        script.push_op(OP_0)
        script.push_op(OP_BOOLOR)
        script.push_op(OP_0)
        script.push_op(OP_0)
        script.push_op(OP_BOOLOR)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'\x01', b'\x01', b''])

    def test23(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_BOOLOR)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test24(self):
        script = Script()
        script.push_op(OP_BOOLOR)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)


    def test25(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_NUMEQUAL)
        script.push_op(OP_0)
        script.push_op(OP_7)
        script.push_op(OP_NUMEQUAL)
        script.push_op(OP_7)
        script.push_op(OP_0)
        script.push_op(OP_NUMEQUAL)
        script.push_op(OP_0)
        script.push_op(OP_0)
        script.push_op(OP_NUMEQUAL)
        script.push_op(OP_9)
        script.push_op(OP_9)
        script.push_op(OP_NUMEQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'', b'', b'', b'\x01', b'\x01'])

    def test26(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_NUMEQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test27(self):
        script = Script()
        script.push_op(OP_NUMEQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test28(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_NUMEQUALVERIFY)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(ScriptVerifyFailure, evaluator.evaluate)
        script = Script()
        script.push_op(OP_0)
        script.push_op(OP_7)
        script.push_op(OP_NUMEQUALVERIFY)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(ScriptVerifyFailure, evaluator.evaluate)
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_0)
        script.push_op(OP_NUMEQUALVERIFY)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(ScriptVerifyFailure, evaluator.evaluate)
        script = Script()
        script.push_op(OP_0)
        script.push_op(OP_0)
        script.push_op(OP_NUMEQUALVERIFY)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [])
        script = Script()
        script.push_op(OP_9)
        script.push_op(OP_9)
        script.push_op(OP_NUMEQUALVERIFY)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [])

    def test29(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_NUMEQUALVERIFY)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test30(self):
        script = Script()
        script.push_op(OP_NUMEQUALVERIFY)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test31(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_NUMNOTEQUAL)
        script.push_op(OP_0)
        script.push_op(OP_7)
        script.push_op(OP_NUMNOTEQUAL)
        script.push_op(OP_7)
        script.push_op(OP_0)
        script.push_op(OP_NUMNOTEQUAL)
        script.push_op(OP_0)
        script.push_op(OP_0)
        script.push_op(OP_NUMNOTEQUAL)
        script.push_op(OP_9)
        script.push_op(OP_9)
        script.push_op(OP_NUMNOTEQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'\x01', b'\x01', b'', b''])

    def test32(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_NUMNOTEQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test33(self):
        script = Script()
        script.push_op(OP_NUMNOTEQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test34(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_LESSTHAN)
        script.push_op(OP_7)
        script.push_op(OP_0)
        script.push_op(OP_LESSTHAN)
        script.push_op(OP_9)
        script.push_op(OP_9)
        script.push_op(OP_LESSTHAN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'', b''])

    def test35(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_LESSTHAN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test36(self):
        script = Script()
        script.push_op(OP_LESSTHAN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test37(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_LESSTHANOREQUAL)
        script.push_op(OP_7)
        script.push_op(OP_0)
        script.push_op(OP_LESSTHANOREQUAL)
        script.push_op(OP_9)
        script.push_op(OP_9)
        script.push_op(OP_LESSTHANOREQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01', b'', b'\x01'])

    def test38(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_LESSTHANOREQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test39(self):
        script = Script()
        script.push_op(OP_LESSTHANOREQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test40(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_GREATERTHAN)
        script.push_op(OP_7)
        script.push_op(OP_0)
        script.push_op(OP_GREATERTHAN)
        script.push_op(OP_9)
        script.push_op(OP_9)
        script.push_op(OP_GREATERTHAN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'', b'\x01', b''])

    def test41(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_GREATERTHAN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test42(self):
        script = Script()
        script.push_op(OP_GREATERTHAN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test43(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_GREATERTHANOREQUAL)
        script.push_op(OP_7)
        script.push_op(OP_0)
        script.push_op(OP_GREATERTHANOREQUAL)
        script.push_op(OP_9)
        script.push_op(OP_9)
        script.push_op(OP_GREATERTHANOREQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'', b'\x01', b'\x01'])

    def test44(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_GREATERTHANOREQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test45(self):
        script = Script()
        script.push_op(OP_GREATERTHANOREQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test46(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_MIN)
        script.push_op(OP_7)
        script.push_op(OP_0)
        script.push_op(OP_MIN)
        script.push_op(OP_9)
        script.push_op(OP_9)
        script.push_op(OP_MIN)
        script.push_op(OP_0)
        script.push_op(OP_1SUB)
        script.push_op(OP_5)
        script.push_op(OP_MIN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x05', b'', b'\x09', b'\xff'])

    def test47(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_MIN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test48(self):
        script = Script()
        script.push_op(OP_MIN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test49(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_MAX)
        script.push_op(OP_7)
        script.push_op(OP_0)
        script.push_op(OP_MAX)
        script.push_op(OP_9)
        script.push_op(OP_9)
        script.push_op(OP_MAX)
        script.push_op(OP_1NEGATE)
        script.push_op(OP_2)
        script.push_op(OP_NEGATE)
        script.push_op(OP_MAX)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x07', b'\x07', b'\x09', b'\xff'])

    def test50(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_MAX)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test51(self):
        script = Script()
        script.push_op(OP_MAX)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test52(self):
        script = Script()
        script.push_op(OP_5)
        script.push_op(OP_7)
        script.push_op(OP_9)
        script.push_op(OP_WITHIN)
        script.push_op(OP_5)
        script.push_op(OP_5)
        script.push_op(OP_9)
        script.push_op(OP_WITHIN)
        script.push_op(OP_7)
        script.push_op(OP_5)
        script.push_op(OP_9)
        script.push_op(OP_WITHIN)
        script.push_op(OP_9)
        script.push_op(OP_5)
        script.push_op(OP_9)
        script.push_op(OP_WITHIN)
        script.push_op(OP_0)
        script.push_op(OP_1NEGATE)
        script.push_op(OP_1)
        script.push_op(OP_WITHIN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'', b'\x01', b'\x01', b'', b'\x01'])

    def test53(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_7)
        script.push_op(OP_WITHIN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test54(self):
        script = Script()
        script.push_op(OP_7)
        script.push_op(OP_WITHIN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

    def test55(self):
        script = Script()
        script.push_op(OP_WITHIN)
        evaluator = ScriptEvaluator(Bitcoin, script)
        self.assertRaises(IndexError, evaluator.evaluate)

class TestCrypto(unittest.TestCase):
    # The following test cases are taken from Bitcoin Core test cases and modified to fit in here

    def test1(self):
        # ["''", "RIPEMD160 0x14 0x9c1185a5c5e9fc54612808977ee8f548b2258d31 EQUAL"],
        script = Script()
        script.push_bytes(b'')
        script.push_op(OP_RIPEMD160)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('9c1185a5c5e9fc54612808977ee8f548b2258d31', reverse=False)])

    def test2(self):
        # ["'a'", "RIPEMD160 0x14 0x0bdc9d2d256b3ee9daae347be6f4dc835a467ffe EQUAL"],
        script = Script()
        script.push_bytes(b'a')
        script.push_op(OP_RIPEMD160)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('0bdc9d2d256b3ee9daae347be6f4dc835a467ffe', reverse=False)])

    def test3(self):
        # ["'abcdefghijklmnopqrstuvwxyz'", "RIPEMD160 0x14 0xf71c27109c692c1b56bbdceb5b9d2865b3708dbc EQUAL"],
        script = Script()
        script.push_bytes(b'abcdefghijklmnopqrstuvwxyz')
        script.push_op(OP_RIPEMD160)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('f71c27109c692c1b56bbdceb5b9d2865b3708dbc', reverse=False)])

    def test4(self):
        # ["''", "SHA1 0x14 0xda39a3ee5e6b4b0d3255bfef95601890afd80709 EQUAL"],
        script = Script()
        script.push_bytes(b'')
        script.push_op(OP_SHA1)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('da39a3ee5e6b4b0d3255bfef95601890afd80709', reverse=False)])

    def test5(self):
        # ["'a'", "SHA1 0x14 0x86f7e437faa5a7fce15d1ddcb9eaeaea377667b8 EQUAL"],
        script = Script()
        script.push_bytes(b'a')
        script.push_op(OP_SHA1)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('86f7e437faa5a7fce15d1ddcb9eaeaea377667b8', reverse=False)])

    def test6(self):
        # ["'abcdefghijklmnopqrstuvwxyz'", "SHA1 0x14 0x32d10c7b8cf96570ca04ce37f2a19d84240d3a89 EQUAL"],
        script = Script()
        script.push_bytes(b'abcdefghijklmnopqrstuvwxyz')
        script.push_op(OP_SHA1)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('32d10c7b8cf96570ca04ce37f2a19d84240d3a89', reverse=False)])

    def test7(self):
        # ["''", "SHA256 0x20 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 EQUAL"],
        script = Script()
        script.push_bytes(b'')
        script.push_op(OP_SHA256)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', reverse=False)])

    def test8(self):
        # ["'a'", "SHA256 0x20 0xca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb EQUAL"],
        script = Script()
        script.push_bytes(b'a')
        script.push_op(OP_SHA256)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb', reverse=False)])

    def test9(self):
        # ["'abcdefghijklmnopqrstuvwxyz'", "SHA256 0x20 0x71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73 EQUAL"],
        script = Script()
        script.push_bytes(b'abcdefghijklmnopqrstuvwxyz')
        script.push_op(OP_SHA256)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73', reverse=False)])

    def test10(self):
        # ["''", "DUP HASH160 SWAP SHA256 RIPEMD160 EQUAL"],
        script = Script()
        script.push_bytes(b'')
        script.push_op(OP_DUP)
        script.push_op(OP_HASH160)
        script.push_op(OP_SWAP)
        script.push_op(OP_SHA256)
        script.push_op(OP_RIPEMD160)
        script.push_op(OP_EQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01'])

    def test11(self):
        # ["''", "DUP HASH256 SWAP SHA256 SHA256 EQUAL"],
        script = Script()
        script.push_bytes(b'')
        script.push_op(OP_DUP)
        script.push_op(OP_HASH256)
        script.push_op(OP_SWAP)
        script.push_op(OP_SHA256)
        script.push_op(OP_SHA256)
        script.push_op(OP_EQUAL)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [b'\x01'])

    def test12(self):
        # ["''", "NOP HASH160 0x14 0xb472a266d0bd89c13706a4132ccfb16f7c3b9fcb EQUAL"],
        script = Script()
        script.push_bytes(b'')
        script.push_op(OP_NOP)
        script.push_op(OP_HASH160)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('b472a266d0bd89c13706a4132ccfb16f7c3b9fcb', reverse=False)])

    def test13(self):
        # ["'a'", "HASH160 NOP 0x14 0x994355199e516ff76c4fa4aab39337b9d84cf12b EQUAL"],
        script = Script()
        script.push_bytes(b'a')
        script.push_op(OP_HASH160)
        script.push_op(OP_NOP)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('994355199e516ff76c4fa4aab39337b9d84cf12b', reverse=False)])

    def test14(self):
        # ["'abcdefghijklmnopqrstuvwxyz'", "HASH160 0x4c 0x14 0xc286a1af0947f58d1ad787385b1c2c4a976f9e71 EQUAL"],
        script = Script()
        script.push_bytes(b'abcdefghijklmnopqrstuvwxyz')
        script.push_op(OP_HASH160)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('c286a1af0947f58d1ad787385b1c2c4a976f9e71', reverse=False)])

    def test15(self):
        # ["''", "HASH256 0x20 0x5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456 EQUAL"],
        script = Script()
        script.push_bytes(b'')
        script.push_op(OP_HASH256)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456', reverse=False)])

    def test16(self):
        # ["'a'", "HASH256 0x20 0xbf5d3affb73efd2ec6c36ad3112dd933efed63c4e1cbffcfa88e2759c144f2d8 EQUAL"],
        script = Script()
        script.push_bytes(b'a')
        script.push_op(OP_HASH256)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('bf5d3affb73efd2ec6c36ad3112dd933efed63c4e1cbffcfa88e2759c144f2d8', reverse=False)])

    def test17(self):
        # ["'abcdefghijklmnopqrstuvwxyz'", "HASH256 0x4c 0x20 0xca139bc10c2f660da42666f72e89a225936fc60f193c161124a672050c434671 EQUAL"],
        script = Script()
        script.push_bytes(b'abcdefghijklmnopqrstuvwxyz')
        script.push_op(OP_HASH256)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertEqual(stack, [hexstring_to_bytes('ca139bc10c2f660da42666f72e89a225936fc60f193c161124a672050c434671', reverse=False)])

    def test18(self):
        script = Script()
        script.push_bytes(b'')
        script.push_op(OP_HASH256)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertNotEqual(stack, [hexstring_to_bytes('ca139bc10c2f660da42666f72e89a225936fc60f193c161124a672050c434671', reverse=False)])

    def test19(self):
        script = Script()
        script.push_bytes(b'')
        script.push_op(OP_HASH160)
        evaluator = ScriptEvaluator(Bitcoin, script)
        stack = evaluator.evaluate()
        self.assertNotEqual(stack, [hexstring_to_bytes('c286a1af0947f58d1ad787385b1c2c4a976f9e71', reverse=False)])

