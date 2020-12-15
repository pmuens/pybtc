import socket

from network.NetworkEnvelope import NetworkEnvelope
from network.VerAckMessage import VerAckMessage
from network.VersionMessage import VersionMessage
from network.PingMessage import PingMessage
from network.PongMessage import PongMessage

from unittest import TestCase


class SimpleNode:
    def __init__(self, host, port=None, testnet=False, logging=False):
        if port is None:
            if testnet:
                port = 18333
            else:
                port = 8333
        self.testnet = testnet
        self.logging = logging
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        self.stream = self.socket.makefile("rb", None)

    def send(self, message):
        envelope = NetworkEnvelope(
            message.command, message.serialize(), testnet=self.testnet
        )
        if self.logging:
            print("sending: {}".format(envelope))
        self.socket.sendall(envelope.serialize())

    def read(self):
        envelope = NetworkEnvelope.parse(self.stream, testnet=self.testnet)
        if self.logging:
            print("receiving: {}".format(envelope))
        return envelope

    def wait_for(self, *message_classes):
        command = None
        command_to_class = {m.command: m for m in message_classes}
        while command not in command_to_class.keys():
            envelope = self.read()
            command = envelope.command
            if command == VersionMessage.command:
                self.send(VerAckMessage())
            elif command == PingMessage.command:
                self.send(PongMessage(envelope.payload))
        return command_to_class[command].parse(envelope.stream())

    def handshake(self):
        version = VersionMessage()
        self.send(version)
        self.wait_for(VerAckMessage)


class SimpleNodeTest(TestCase):
    def test_handshake(self):
        node = SimpleNode("testnet.programmingbitcoin.com", testnet=True)
        node.handshake()
