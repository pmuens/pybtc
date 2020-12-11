import hashlib
from unittest import TestCase


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


class UtilsTest(TestCase):
    def test_encode_base58(self):
        h = "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d"
        result = encode_base58(bytes.fromhex(h))
        self.assertEqual(result, "9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6")

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
