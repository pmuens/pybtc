from shared.utils import int_to_little_endian, encode_varint

from unittest import TestCase


class GetHeadersMessage:
    command = b"getheaders"

    def __init__(self, version=70015, num_hashes=1, start_block=None, end_block=None):
        self.version = version
        self.num_hashes = num_hashes
        if start_block is None:
            raise RuntimeError("a start block is required")
        self.start_block = start_block
        if end_block is None:
            self.end_block = b"\x00" * 32
        else:
            self.end_block = end_block

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(self.num_hashes)
        result += self.start_block[::-1]
        result += self.end_block[::-1]
        return result


class GetHeadersMessageTest(TestCase):
    def test_serialize(self):
        block_hex = "0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3"
        gh = GetHeadersMessage(start_block=bytes.fromhex(block_hex))
        self.assertEqual(
            gh.serialize().hex(),
            "7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        )
