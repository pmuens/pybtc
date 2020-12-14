from io import BytesIO
from logging import getLogger
from unittest import TestCase

from script.op import OP_CODE_FUNCTIONS, OP_CODE_NAMES
from shared.utils import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)


def p2pkh_script(h160):
    return Script([0x76, 0xA9, h160, 0x88, 0xAC])


LOGGER = getLogger(__name__)


class Script:
    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __add__(self, other):
        return Script(self.cmds + other.cmds)

    def raw_serialize(self):
        result = b""
        for cmd in self.cmds:
            if type(cmd) == int:
                result += int_to_little_endian(cmd, 1)
            else:
                length = len(cmd)
                if length < 75:
                    result += int_to_little_endian(length, 1)
                # OP_PUSHDATA1
                elif length > 75 and length < 0x100:
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                # OP_PUSHDATA2
                elif length >= 0x100 and length <= 520:
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError("too long an cmd")
                result += cmd
        return result

    def serialize(self):
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result

    def evaluate(self, z):
        cmds = self.cmds[:]
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            if type(cmd) == int:
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100):
                    if not operation(stack, cmds):
                        LOGGER.info("bad op: {}".format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (107, 108):
                    if not operation(stack, altstack):
                        LOGGER.info("bad op: {}".format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (172, 173, 174, 175):
                    if not operation(stack, z):
                        LOGGER.info("bad op: {}".format(OP_CODE_NAMES[cmd]))
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info("bad op: {}".format(OP_CODE_NAMES[cmd]))
                        return False
            else:
                stack.append(cmd)
        if len(stack) == 0:
            return False
        if stack.pop() == b"":
            return False
        return True

    @classmethod
    def parse(cls, s):
        length = read_varint(s)
        cmds = []
        count = 0
        while count < length:
            current = s.read(1)
            count += 1
            current_byte = current[0]
            if current_byte >= 1 and current_byte <= 75:
                n = current_byte
                cmds.append(s.read(n))
                count += n
            # OP_PUSHDATA1
            elif current_byte == 76:
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            # OP_PUSHDATA2
            elif current_byte == 77:
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                op_code = current_byte
                cmds.append(op_code)
        if count != length:
            raise SyntaxError("parsing script failed")
        return cls(cmds)


class ScriptTest(TestCase):
    def test_evaluate0(self):
        z = 0x7C076FF316692A3D7EB3C3BB0F8B1488CF72E1AFCD929E29307032997A838A3D
        sec = bytes.fromhex(
            "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34"
        )
        sig = bytes.fromhex(
            "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601"
        )
        # 0xAC = 172 = OP_CHECKSIG
        script_pubkey = Script([sec, 0xAC])
        script_sig = Script([sig])
        combined = script_sig + script_pubkey
        self.assertTrue(combined.evaluate(z))

    def test_evaluate1(self):
        script_pubkey = Script([0x76, 0x76, 0x95, 0x93, 0x56, 0x87])
        script_sig = Script([0x52])
        combined_script = script_sig + script_pubkey
        self.assertTrue(combined_script.evaluate(0))

    def test_parse(self):
        script_pubkey = BytesIO(
            bytes.fromhex(
                "6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937"
            )
        )
        script = Script.parse(script_pubkey)
        want = bytes.fromhex(
            "304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601"
        )
        self.assertEqual(script.cmds[0].hex(), want.hex())
        want = bytes.fromhex(
            "035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937"
        )
        self.assertEqual(script.cmds[1], want)

    def test_serialize(self):
        want = "6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937"
        script_pubkey = BytesIO(bytes.fromhex(want))
        script = Script.parse(script_pubkey)
        self.assertEqual(script.serialize().hex(), want)
