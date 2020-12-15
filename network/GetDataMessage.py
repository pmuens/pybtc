from shared.utils import encode_varint, int_to_little_endian

from unittest import TestCase

TX_DATA_TYPE = 1
BLOCK_DATA_TYPE = 2
FILTERED_BLOCK_DATA_TYPE = 3
COMPACT_BLOCK_DATA_TYPE = 4


class GetDataMessage:
    command = b"getdata"

    def __init__(self):
        self.data = []

    def add_data(self, data_type, identifier):
        self.data.append((data_type, identifier))

    def serialize(self):
        result = encode_varint(len(self.data))
        for data_type, identifier in self.data:
            result += int_to_little_endian(data_type, 4)
            result += identifier[::-1]
        return result


class GetDataMessageTest(TestCase):
    def test_serialize(self):
        hex_msg = "020300000030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000030000001049847939585b0652fba793661c361223446b6fc41089b8be00000000000000"
        get_data = GetDataMessage()
        block1 = bytes.fromhex(
            "00000000000000cac712b726e4326e596170574c01a16001692510c44025eb30"
        )
        get_data.add_data(FILTERED_BLOCK_DATA_TYPE, block1)
        block2 = bytes.fromhex(
            "00000000000000beb88910c46f6b442312361c6693a7fb52065b583979844910"
        )
        get_data.add_data(FILTERED_BLOCK_DATA_TYPE, block2)
        self.assertEqual(get_data.serialize().hex(), hex_msg)
