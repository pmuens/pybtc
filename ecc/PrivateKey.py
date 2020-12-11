import hmac
import hashlib
from random import randint
from unittest import TestCase

from ecc.S256Point import G, N
from ecc.Signature import Signature
from shared.utils import encode_base58_checksum


class PrivateKey:
    def __init__(self, secret):
        self.secret = secret
        self.point = secret * G

    def hex(self):
        return "{:x}".format(self.secret).zfill(64)

    def sign(self, z):
        k = self.deterministic_k(z)
        r = (k * G).x.num
        k_inv = pow(k, N - 2, N)
        s = (z + r * self.secret) * k_inv % N
        if s > N / 2:
            s = N - s
        return Signature(r, s)

    def deterministic_k(self, z):
        k = b"\x00" * 32
        v = b"\x01" * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, "big")
        secret_bytes = self.secret.to_bytes(32, "big")
        s256 = hashlib.sha256
        k = hmac.new(k, v + b"\x00" + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b"\x01" + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, "big")
            if candidate >= 1 and candidate < N:
                return candidate
            k = hmac.new(k, v + b"\x00", s256).digest()
            v = hmac.new(k, v, s256).digest()

    def wif(self, compressed=True, testnet=False):
        secret_bytes = self.secret.to_bytes(32, "big")
        if testnet:
            prefix = b"\xef"
        else:
            prefix = b"\x80"
        if compressed:
            suffix = b"\x01"
        else:
            suffix = b""
        return encode_base58_checksum(prefix + secret_bytes + suffix)


class PrivateKeyTest(TestCase):
    def test_sign(self):
        pk = PrivateKey(randint(0, N))
        z = randint(0, 2 ** 256)
        sig = pk.sign(z)
        self.assertTrue(pk.point.verify(z, sig))

    def test_wif_compressed_testnet(self):
        from ecc.PrivateKey import PrivateKey

        priv = PrivateKey(5003)
        result = priv.wif(compressed=True, testnet=True)
        self.assertEqual(result, "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN8rFTv2sfUK")

    def test_wif_uncompressed_testnet(self):
        from ecc.PrivateKey import PrivateKey

        priv = PrivateKey(2021 ** 5)
        result = priv.wif(compressed=False, testnet=True)
        self.assertEqual(result, "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjpWAxgzczjbCwxic")

    def test_wif_compressed_mainnet(self):
        from ecc.PrivateKey import PrivateKey

        priv = PrivateKey(0x54321DEADBEEF)
        result = priv.wif()
        self.assertEqual(result, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgiuQJv1h8Ytr2S53a")
