from unittest import TestCase

from merkle.MerkleTree import MerkleTree
from shared.utils import bytes_to_bit_field, little_endian_to_int, read_varint


class MerkleBlock:
    def __init__(
        self,
        version,
        prev_block,
        merkle_root,
        timestamp,
        bits,
        nonce,
        total,
        hashes,
        flags,
    ):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.total = total
        self.hashes = hashes
        self.flags = flags

    def __repr__(self):
        result = "{}\n".format(self.total)
        for h in self.hashes:
            result += "\t{}\n".format(h.hex())
        result += "{}".format(self.flags.hex())

    def is_valid(self):
        flag_bits = bytes_to_bit_field(self.flags)
        hashes = [h[::-1] for h in self.hashes]
        merkle_tree = MerkleTree(self.total)
        merkle_tree.populate_tree(flag_bits, hashes)
        return merkle_tree.root()[::-1] == self.merkle_root

    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        prev_block = s.read(32)[::-1]
        merkle_root = s.read(32)[::-1]
        timestamp = little_endian_to_int(s.read(4))
        bits = s.read(4)
        nonce = s.read(4)
        total = little_endian_to_int(s.read(4))
        num_hashes = read_varint(s)
        hashes = []
        for _ in range(num_hashes):
            hashes.append(s.read(32)[::-1])
        flags_length = read_varint(s)
        flags = s.read(flags_length)
        return cls(
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
            total,
            hashes,
            flags,
        )


class MerkleBlockTest(TestCase):
    def test_parse(self):
        from io import BytesIO

        hex_merkle_block = "00000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670bf0d00000aba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cbaee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763cef8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274cdfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb6226103b55635"
        mb = MerkleBlock.parse(BytesIO(bytes.fromhex(hex_merkle_block)))
        version = 0x20000000
        self.assertEqual(mb.version, version)
        merkle_root_hex = (
            "ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4"
        )
        merkle_root = bytes.fromhex(merkle_root_hex)[::-1]
        self.assertEqual(mb.merkle_root, merkle_root)
        prev_block_hex = (
            "df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000"
        )
        prev_block = bytes.fromhex(prev_block_hex)[::-1]
        self.assertEqual(mb.prev_block, prev_block)
        timestamp = little_endian_to_int(bytes.fromhex("dc7c835b"))
        self.assertEqual(mb.timestamp, timestamp)
        bits = bytes.fromhex("67d8001a")
        self.assertEqual(mb.bits, bits)
        nonce = bytes.fromhex("c157e670")
        self.assertEqual(mb.nonce, nonce)
        total = little_endian_to_int(bytes.fromhex("bf0d0000"))
        self.assertEqual(mb.total, total)
        hex_hashes = [
            "ba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a",
            "7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d",
            "34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2",
            "158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cba",
            "ee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763ce",
            "f8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097",
            "c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d",
            "6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543",
            "d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274c",
            "dfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb62261",
        ]
        hashes = [bytes.fromhex(h)[::-1] for h in hex_hashes]
        self.assertEqual(mb.hashes, hashes)
        flags = bytes.fromhex("b55635")
        self.assertEqual(mb.flags, flags)

    def test_is_valid(self):
        from io import BytesIO

        hex_merkle_block = "00000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670bf0d00000aba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cbaee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763cef8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274cdfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb6226103b55635"
        mb = MerkleBlock.parse(BytesIO(bytes.fromhex(hex_merkle_block)))
        self.assertTrue(mb.is_valid())
