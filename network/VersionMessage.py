import time
from random import randint
from unittest import TestCase

from shared.utils import encode_varint, int_to_little_endian


class VersionMessage:
    command = b"version"

    def __init__(
        self,
        version=70015,
        services=0,
        timestamp=None,
        receiver_services=0,
        receiver_ip=b"\x00\x00\x00\x00",
        receiver_port=8333,
        sender_services=0,
        sender_ip=b"\x00\x00\x00\x00",
        sender_port=8333,
        nonce=None,
        user_agent=b"/programmingbitcoin:0.1/",
        latest_block=0,
        relay=False,
    ):
        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2 ** 64), 8)
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += int_to_little_endian(self.services, 8)
        result += int_to_little_endian(self.timestamp, 8)
        result += int_to_little_endian(self.receiver_services, 8)
        result += b"\x00" * 10 + b"\xff\xff" + self.receiver_ip
        result += self.receiver_port.to_bytes(2, "big")
        result += int_to_little_endian(self.sender_services, 8)
        result += b"\x00" * 10 + b"\xff\xff" + self.sender_ip
        result += self.sender_port.to_bytes(2, "big")
        result += self.nonce
        result += encode_varint(len(self.user_agent))
        result += self.user_agent
        result += int_to_little_endian(self.latest_block, 4)
        if self.relay:
            result += b"\x01"
        else:
            result += b"\x00"
        return result


class VersionMessageTest(TestCase):
    def test_serialize(self):
        v = VersionMessage(timestamp=0, nonce=b"\x00" * 8)
        self.assertEqual(
            v.serialize().hex(),
            "7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d0000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000000",
        )
