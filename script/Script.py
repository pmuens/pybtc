from io import BytesIO
from hashlib import sha256
from logging import getLogger
from unittest import TestCase

from script.op import OP_CODE_FUNCTIONS, OP_CODE_NAMES, op_equal, op_hash160, op_verify
from shared.utils import (
    encode_varint,
    h160_to_p2pkh_address,
    h160_to_p2sh_address,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)


def p2pkh_script(h160):
    return Script([0x76, 0xA9, h160, 0x88, 0xAC])


def p2sh_script(h160):
    return Script([0xA9, h160, 0x87])


def p2wpkh_script(h160):
    return Script([0x00, h160])


def p2wsh_script(h256):
    return Script([0x00, h256])


LOGGER = getLogger(__name__)


class Script:
    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = "OP_[{}]".format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return " ".join(result)

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

    def evaluate(self, z, witness):
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
                if (
                    len(cmds) == 3
                    and cmds[0] == 0xA9
                    and type(cmds[1]) == bytes
                    and len(cmds[1]) == 20
                    and cmds[2] == 0x87
                ):
                    redeem_script = encode_varint(len(cmd)) + cmd
                    cmds.pop()
                    h160 = cmds.pop()
                    cmds.pop()
                    if not op_hash160(stack):
                        return False
                    stack.append(h160)
                    if not op_equal(stack):
                        return False
                    if not op_verify(stack):
                        LOGGER.info("bad p2sh h160")
                        return False
                    redeem_script = encode_varint(len(cmd)) + cmd
                    stream = BytesIO(redeem_script)
                    cmds.extend(Script.parse(stream).cmds)
                if len(stack) == 2 and stack[0] == b"" and len(stack[1]) == 20:
                    h160 = stack.pop()
                    stack.pop()
                    cmds.extend(witness)
                    cmds.extend(p2pkh_script(h160).cmds)
                if len(stack) == 2 and stack[0] == b"" and len(stack[1]) == 32:
                    s256 = stack.pop()
                    stack.pop()
                    cmds.extend(witness[:-1])
                    witness_script = witness[-1]
                    if s256 != sha256(witness_script):
                        print(
                            "bad sha256 {} vs {}".format(
                                s256.hex(), sha256(witness_script).hex()
                            )
                        )
                        return False
                    stream = BytesIO(
                        encode_varint(len(witness_script)) + witness_script
                    )
                    witness_script_cmds = Script.parse(stream).cmds
                    cmds.extend(witness_script_cmds)
        if len(stack) == 0:
            return False
        if stack.pop() == b"":
            return False
        return True

    def is_p2pkh_script_pubkey(self):
        return (
            len(self.cmds) == 5
            and self.cmds[0] == 0x76
            and self.cmds[1] == 0xA9
            and type(self.cmds[2]) == bytes
            and len(self.cmds[2]) == 20
            and self.cmds[3] == 0x88
            and self.cmds[4] == 0xAC
        )

    def is_p2sh_script_pubkey(self):
        return (
            len(self.cmds) == 3
            and self.cmds[0] == 0xA9
            and type(self.cmds[1]) == bytes
            and len(self.cmds[1]) == 20
            and self.cmds[2] == 0x87
        )

    def is_p2wpkh_script_pubkey(self):
        return (
            len(self.cmds) == 2
            and self.cmds[0] == 0x00
            and type(self.cmds[1]) == bytes
            and len(self.cmds[1]) == 20
        )

    def is_p2wsh_script_pubkey(self):
        return (
            len(self.cmds) == 2
            and self.cmds[0] == 0x00
            and type(self.cmds[1]) == bytes
            and len(self.cmds[1]) == 32
        )

    def address(self, testnet=False):
        if self.is_p2pkh_script_pubkey():
            h160 = self.cmds[2]
            return h160_to_p2pkh_address(h160, testnet)
        elif self.is_p2sh_script_pubkey():
            h160 = self.cmds[1]
            return h160_to_p2sh_address(h160, testnet)
        raise ValueError("Unknown ScriptPubKey")

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

    def test_address(self):
        from shared.utils import decode_base58

        address_1 = "1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa"
        h160 = decode_base58(address_1)
        p2pkh_script_pubkey = p2pkh_script(h160)
        self.assertEqual(p2pkh_script_pubkey.address(), address_1)
        address_2 = "mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q"
        self.assertEqual(p2pkh_script_pubkey.address(testnet=True), address_2)
        address_3 = "3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh"
        h160 = decode_base58(address_3)
        p2sh_script_pubkey = p2sh_script(h160)
        self.assertEqual(p2sh_script_pubkey.address(), address_3)
        address_4 = "2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B"
        self.assertEqual(p2sh_script_pubkey.address(testnet=True), address_4)
