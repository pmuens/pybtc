from network.GenericMessage import GenericMessage
from shared.utils import (
    bit_field_to_bytes,
    encode_varint,
    int_to_little_endian,
    murmur3,
)

from unittest import TestCase

BIP37_CONSTANT = 0xFBA4C795


class BloomFilter:
    def __init__(self, size, function_count, tweak):
        self.size = size
        self.bit_field = [0] * (size * 8)
        self.function_count = function_count
        self.tweak = tweak

    def add(self, item):
        for i in range(self.function_count):
            seed = i * BIP37_CONSTANT + self.tweak
            h = murmur3(item, seed=seed)
            bit = h % (self.size * 8)
            self.bit_field[bit] = 1

    def filter_bytes(self):
        return bit_field_to_bytes(self.bit_field)

    def filterload(self, flag=1):
        payload = encode_varint(self.size)
        payload += self.filter_bytes()
        payload += int_to_little_endian(self.function_count, 4)
        payload += int_to_little_endian(self.tweak, 4)
        payload += int_to_little_endian(flag, 1)
        return GenericMessage(b"filterload", payload)


class BloomFilterTest(TestCase):
    def test_add(self):
        bf = BloomFilter(10, 5, 99)
        item = b"Hello World"
        bf.add(item)
        expected = "0000000a080000000140"
        self.assertEqual(bf.filter_bytes().hex(), expected)
        item = b"Goodbye!"
        bf.add(item)
        expected = "4000600a080000010940"
        self.assertEqual(bf.filter_bytes().hex(), expected)

    def test_filterload(self):
        bf = BloomFilter(10, 5, 99)
        item = b"Hello World"
        bf.add(item)
        item = b"Goodbye!"
        bf.add(item)
        expected = "0a4000600a080000010940050000006300000001"
        self.assertEqual(bf.filterload().serialize().hex(), expected)
