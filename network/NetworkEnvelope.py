from io import BytesIO
from unittest import TestCase

from shared.utils import int_to_little_endian, little_endian_to_int, hash256

NETWORK_MAGIC = b"\xf9\xbe\xb4\xd9"
TESTNET_NETWORK_MAGIC = b"\x0b\x11\x09\x07"


class NetworkEnvelope:
    def __init__(self, command, payload, testnet=False):
        self.command = command
        self.payload = payload
        if testnet:
            self.magic = TESTNET_NETWORK_MAGIC
        else:
            self.magic = NETWORK_MAGIC

    def __repr__(self):
        return "{}: {}".format(self.command.decode("ascii"), self.payload.hex())

    def serialize(self):
        result = self.magic
        result += self.command + b"\x00" * (12 - len(self.command))
        result += int_to_little_endian(len(self.payload), 4)
        result += hash256(self.payload)[:4]
        result += self.payload
        return result

    def stream(self):
        return BytesIO(self.payload)

    @classmethod
    def parse(cls, s, testnet=False):
        magic = s.read(4)
        if magic == b"":
            raise IOError("Connection reset!")
        if testnet:
            expected_magic = TESTNET_NETWORK_MAGIC
        else:
            expected_magic = NETWORK_MAGIC
        if magic != expected_magic:
            raise SyntaxError(
                "magic is not right {} vs {}".format(magic.hex(), expected_magic.hex())
            )
        command = s.read(12)
        command = command.strip(b"\x00")
        payload_length = little_endian_to_int(s.read(4))
        checksum = s.read(4)
        payload = s.read(payload_length)
        calculated_checksum = hash256(payload)[:4]
        if calculated_checksum != checksum:
            raise IOError("checksum does not match")
        return cls(command, payload, testnet=testnet)


class NetworkEnvelopeTest(TestCase):
    def test_parse(self):
        msg = bytes.fromhex("f9beb4d976657261636b000000000000000000005df6e0e2")
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.command, b"verack")
        self.assertEqual(envelope.payload, b"")
        msg = bytes.fromhex(
            "f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001"
        )
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.command, b"version")
        self.assertEqual(envelope.payload, msg[24:])

    def test_serialize(self):
        msg = bytes.fromhex("f9beb4d976657261636b000000000000000000005df6e0e2")
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.serialize(), msg)
        msg = bytes.fromhex(
            "f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001"
        )
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.serialize(), msg)
