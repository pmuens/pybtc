import hashlib
from unittest import TestCase


SIGHASH_ALL = 1
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode_base58(s):
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, "big")
    prefix = "1" * count
    result = ""
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def decode_base58(s):
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)
    combined = num.to_bytes(25, byteorder="big")
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError(
            "bad address: {} {}".format(checksum, hash256(combined[:-4])[:4])
        )
    return combined[1:-4]


def h160_to_p2pkh_address(h160, testnet=False):
    if testnet:
        prefix = b"\x6f"
    else:
        prefix = b"\x00"
    return encode_base58_checksum(prefix + h160)


def h160_to_p2sh_address(h160, testnet=False):
    if testnet:
        prefix = b"\xc4"
    else:
        prefix = b"\x05"
    return encode_base58_checksum(prefix + h160)


def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def hash160(s):
    return hashlib.new("ripemd160", hashlib.sha256(s).digest()).digest()


def encode_base58_checksum(b):
    return encode_base58(b + hash256(b)[:4])


def little_endian_to_int(b):
    return int.from_bytes(b, "little")


def int_to_little_endian(n, length):
    return n.to_bytes(length, "little")


def read_varint(s):
    i = s.read(1)[0]
    if i == 0xFD:
        return little_endian_to_int(s.read(2))
    elif i == 0xFE:
        return little_endian_to_int(s.read(4))
    elif i == 0xFF:
        return little_endian_to_int(s.read(8))
    return i


def encode_varint(i):
    if i < 0xFD:
        return bytes([i])
    elif i < 0x1000:
        return b"\xfd" + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b"\xfe" + int_to_little_endian(i, 4)
    elif i < 0x0000000000000000:
        return b"\xff" + int_to_little_endian(i, 8)
    else:
        raise ValueError("integer too large: {}".format(i))


class UtilsTest(TestCase):
    def test_base58(self):
        addr = "mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf"
        h160 = decode_base58(addr).hex()
        want = "507b27411ccf7f16f10297de6cef3f291623eddf"
        self.assertEqual(h160, want)
        got = encode_base58_checksum(b"\x6f" + bytes.fromhex(h160))
        self.assertEqual(got, addr)

    def test_little_endian_to_int(self):
        h = bytes.fromhex("99c3980000000000")
        want = 10011545
        self.assertEqual(little_endian_to_int(h), want)
        h = bytes.fromhex("a135ef0100000000")
        want = 32454049
        self.assertEqual(little_endian_to_int(h), want)

    def test_int_to_little_endian(self):
        n = 1
        want = b"\x01\x00\x00\x00"
        self.assertEqual(int_to_little_endian(n, 4), want)
        n = 10011545
        want = b"\x99\xc3\x98\x00\x00\x00\x00\x00"
        self.assertEqual(int_to_little_endian(n, 8), want)

    def test_encode_varint(self):
        from io import BytesIO

        value = 4711
        self.assertEqual(read_varint(BytesIO(encode_varint(value))), value)

    def test_p2pkh_address(self):
        h160 = bytes.fromhex("74d691da1574e6b3c192ecfb52cc8984ee7b6c56")
        want = "1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa"
        self.assertEqual(h160_to_p2pkh_address(h160, testnet=False), want)
        want = "mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q"
        self.assertEqual(h160_to_p2pkh_address(h160, testnet=True), want)

    def test_p2sh_address(self):
        h160 = bytes.fromhex("74d691da1574e6b3c192ecfb52cc8984ee7b6c56")
        want = "3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh"
        self.assertEqual(h160_to_p2sh_address(h160, testnet=False), want)
        want = "2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B"
        self.assertEqual(h160_to_p2sh_address(h160, testnet=True), want)
