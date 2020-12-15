from unittest import TestCase

from shared.utils import (
    bits_to_target,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    merkle_root,
)


class Block:
    def __init__(
        self, version, prev_block, merkle_root, timestamp, bits, nonce, tx_hashes=None
    ):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += self.prev_block[::-1]
        result += self.merkle_root[::-1]
        result += int_to_little_endian(self.timestamp, 4)
        result += self.bits
        result += self.nonce
        return result

    def hash(self):
        s = self.serialize()
        sha = hash256(s)
        return sha[::-1]

    def bip9(self):
        return self.version >> 29 == 0b001

    def bip91(self):
        return self.version >> 4 & 1 == 1

    def bip141(self):
        return self.version >> 1 & 1 == 1

    def target(self):
        return bits_to_target(self.bits)

    def difficulty(self):
        lowest = 0xFFFF * 256 ** (0x1D - 3)
        return lowest / self.target()

    def check_pow(self):
        sha = hash256(self.serialize())
        proof = little_endian_to_int(sha)
        return proof < self.target()

    def validate_merkle_root(self):
        hashes = [h[::-1] for h in self.tx_hashes]
        root = merkle_root(hashes)
        return root[::-1] == self.merkle_root

    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        prev_block = s.read(32)[::-1]
        merkle_root = s.read(32)[::-1]
        timestamp = little_endian_to_int(s.read(4))
        bits = s.read(4)
        nonce = s.read(4)
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)


class BlockTest(TestCase):
    def test_parse(self):
        from io import BytesIO

        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertEqual(block.version, 0x20000002)
        want = bytes.fromhex(
            "000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e"
        )
        self.assertEqual(block.prev_block, want)
        want = bytes.fromhex(
            "be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b"
        )
        self.assertEqual(block.merkle_root, want)
        self.assertEqual(block.timestamp, 0x59A7771E)
        self.assertEqual(block.bits, bytes.fromhex("e93c0118"))
        self.assertEqual(block.nonce, bytes.fromhex("a4ffd71d"))

    def test_serialize(self):
        from io import BytesIO

        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertEqual(block.serialize(), block_raw)

    def test_hash(self):
        from io import BytesIO

        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertEqual(
            block.hash(),
            bytes.fromhex(
                "0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523"
            ),
        )

    def test_bip9(self):
        from io import BytesIO

        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertTrue(block.bip9())
        block_raw = bytes.fromhex(
            "0400000039fa821848781f027a2e6dfabbf6bda920d9ae61b63400030000000000000000ecae536a304042e3154be0e3e9a8220e5568c3433a9ab49ac4cbb74f8df8e8b0cc2acf569fb9061806652c27"
        )
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertFalse(block.bip9())

    def test_bip91(self):
        from io import BytesIO

        block_raw = bytes.fromhex(
            "1200002028856ec5bca29cf76980d368b0a163a0bb81fc192951270100000000000000003288f32a2831833c31a25401c52093eb545d28157e200a64b21b3ae8f21c507401877b5935470118144dbfd1"
        )
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertTrue(block.bip91())
        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertFalse(block.bip91())

    def test_bip141(self):
        from io import BytesIO

        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertTrue(block.bip141())
        block_raw = bytes.fromhex(
            "0000002066f09203c1cf5ef1531f24ed21b1915ae9abeb691f0d2e0100000000000000003de0976428ce56125351bae62c5b8b8c79d8297c702ea05d60feabb4ed188b59c36fa759e93c0118b74b2618"
        )
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertFalse(block.bip141())

    def test_target(self):
        from io import BytesIO

        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertEqual(
            block.target(), 0x13CE9000000000000000000000000000000000000000000
        )
        self.assertEqual(int(block.difficulty()), 888171856257)

    def test_difficulty(self):
        from io import BytesIO

        block_raw = bytes.fromhex(
            "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
        )
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertEqual(int(block.difficulty()), 888171856257)

    def test_check_pow(self):
        from io import BytesIO

        block_raw = bytes.fromhex(
            "04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1"
        )
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertTrue(block.check_pow())
        block_raw = bytes.fromhex(
            "04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec0"
        )
        stream = BytesIO(block_raw)
        block = Block.parse(stream)
        self.assertFalse(block.check_pow())

    def test_validate_merkle_root(self):
        from io import BytesIO

        hashes_hex = [
            "f54cb69e5dc1bd38ee6901e4ec2007a5030e14bdd60afb4d2f3428c88eea17c1",
            "c57c2d678da0a7ee8cfa058f1cf49bfcb00ae21eda966640e312b464414731c1",
            "b027077c94668a84a5d0e72ac0020bae3838cb7f9ee3fa4e81d1eecf6eda91f3",
            "8131a1b8ec3a815b4800b43dff6c6963c75193c4190ec946b93245a9928a233d",
            "ae7d63ffcb3ae2bc0681eca0df10dda3ca36dedb9dbf49e33c5fbe33262f0910",
            "61a14b1bbdcdda8a22e61036839e8b110913832efd4b086948a6a64fd5b3377d",
            "fc7051c8b536ac87344c5497595d5d2ffdaba471c73fae15fe9228547ea71881",
            "77386a46e26f69b3cd435aa4faac932027f58d0b7252e62fb6c9c2489887f6df",
            "59cbc055ccd26a2c4c4df2770382c7fea135c56d9e75d3f758ac465f74c025b8",
            "7c2bf5687f19785a61be9f46e031ba041c7f93e2b7e9212799d84ba052395195",
            "08598eebd94c18b0d59ac921e9ba99e2b8ab7d9fccde7d44f2bd4d5e2e726d2e",
            "f0bb99ef46b029dd6f714e4b12a7d796258c48fee57324ebdc0bbc4700753ab1",
        ]
        hashes = [bytes.fromhex(x) for x in hashes_hex]
        stream = BytesIO(
            bytes.fromhex(
                "00000020fcb19f7895db08cadc9573e7915e3919fb76d59868a51d995201000000000000acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed691cfa85916ca061a00000000"
            )
        )
        block = Block.parse(stream)
        block.tx_hashes = hashes
        self.assertTrue(block.validate_merkle_root())
