import hashlib
from unittest import TestCase


SIGHASH_ALL = 1
TWO_WEEKS = 60 * 60 * 24 * 14
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


def bits_to_target(bits):
    exponent = bits[-1]
    coefficient = little_endian_to_int(bits[:-1])
    return coefficient * 256 ** (exponent - 3)


def target_to_bits(target):
    raw_bytes = target.to_bytes(32, "big")
    raw_bytes = raw_bytes.lstrip(b"\x00")
    if raw_bytes[0] > 0x7F:
        exponent = len(raw_bytes) + 1
        coefficient = b"\x00" + raw_bytes[:2]
    else:
        exponent = len(raw_bytes)
        coefficient = raw_bytes[:3]
    new_bits = coefficient[::-1] + bytes([exponent])
    return new_bits


def calculate_new_bits(previous_bits, time_differential):
    if time_differential > TWO_WEEKS * 4:
        time_differential = TWO_WEEKS * 4
    if time_differential < TWO_WEEKS // 4:
        time_differential = TWO_WEEKS // 4
    new_target = bits_to_target(previous_bits) * time_differential // TWO_WEEKS
    return target_to_bits(new_target)


def merkle_parent(hash1, hash2):
    return hash256(hash1 + hash2)


def merkle_parent_level(hashes):
    if len(hashes) == 1:
        raise RuntimeError("Cannot take a parent level with only 1 item")
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
    parent_level = []
    for i in range(0, len(hashes), 2):
        parent = merkle_parent(hashes[i], hashes[i + 1])
        parent_level.append(parent)
    return parent_level


def merkle_root(hashes):
    current_level = hashes
    while len(current_level) > 1:
        current_level = merkle_parent_level(current_level)
    return current_level[0]


def bit_field_to_bytes(bit_field):
    if len(bit_field) % 8 != 0:
        raise RuntimeError("bit_field does not have a length that is divisible by 8")
    result = bytearray(len(bit_field) // 8)
    for i, bit in enumerate(bit_field):
        byte_index, bit_index = divmod(i, 8)
        if bit:
            result[byte_index] |= 1 << bit_index
    return bytes(result)


def bytes_to_bit_field(some_bytes):
    flag_bits = []
    for byte in some_bytes:
        for _ in range(8):
            flag_bits.append(byte & 1)
            byte >>= 1
    return flag_bits


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

    def test_calculate_new_bits(self):
        prev_bits = bytes.fromhex("54d80118")
        time_differential = 302400
        want = bytes.fromhex("00157617")
        self.assertEqual(calculate_new_bits(prev_bits, time_differential), want)

    def test_merkle_parent(self):
        tx_hash0 = bytes.fromhex(
            "c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5"
        )
        tx_hash1 = bytes.fromhex(
            "c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5"
        )
        want = bytes.fromhex(
            "8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd"
        )
        self.assertEqual(merkle_parent(tx_hash0, tx_hash1), want)

    def test_merkle_parent_level(self):
        hex_hashes = [
            "c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5",
            "c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5",
            "f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0",
            "3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181",
            "10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae",
            "7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161",
            "8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc",
            "dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877",
            "b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59",
            "95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c",
            "2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908",
        ]
        tx_hashes = [bytes.fromhex(x) for x in hex_hashes]
        want_hex_hashes = [
            "8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd",
            "7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800",
            "ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7",
            "68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069",
            "43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27",
            "1796cd3ca4fef00236e07b723d3ed88e1ac433acaaa21da64c4b33c946cf3d10",
        ]
        want_tx_hashes = [bytes.fromhex(x) for x in want_hex_hashes]
        self.assertEqual(merkle_parent_level(tx_hashes), want_tx_hashes)

    def test_merkle_root(self):
        hex_hashes = [
            "c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5",
            "c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5",
            "f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0",
            "3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181",
            "10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae",
            "7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161",
            "8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc",
            "dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877",
            "b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59",
            "95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c",
            "2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908",
            "b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0",
        ]
        tx_hashes = [bytes.fromhex(x) for x in hex_hashes]
        want_hex_hash = (
            "acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6"
        )
        want_hash = bytes.fromhex(want_hex_hash)
        self.assertEqual(merkle_root(tx_hashes), want_hash)
