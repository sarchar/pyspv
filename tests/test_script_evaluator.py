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

