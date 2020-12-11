from unittest.case import TestCase

from ecc.Point import Point
from ecc.S256Field import S256Field, P
from shared.utils import encode_base58_checksum, hash160

A = 0
B = 7
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class S256Point(Point):
    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __repr__(self):
        if self.x is None:
            return "S256Point(infinity)"
        else:
            return "S256Point({}, {})".format(self.x, self.y)

    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)

    def verify(self, z, sig):
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total = u * G + v * self
        return total.x.num == sig.r

    def sec(self, compressed=True):
        # Returns the binary version of the SEC format
        if compressed:
            if self.y.num % 2 == 0:
                return b"\x02" + self.x.num.to_bytes(32, "big")
            else:
                return b"\x03" + self.x.num.to_bytes(32, "big")
        return b"\x04" + self.x.num.to_bytes(32, "big") + self.y.num.to_bytes(32, "big")

    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))

    def address(self, compressed=True, testnet=False):
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b"\x6f"
        else:
            prefix = b"\x00"
        return encode_base58_checksum(prefix + h160)

    @classmethod
    def parse(self, sec_bin):
        # Returns a Point from a SEC binary
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], "big")
            y = int.from_bytes(sec_bin[33:65], "big")
            return S256Point(x, y)
        is_even = sec_bin[0] == 2
        x = S256Field(int.from_bytes(sec_bin[1:], "big"))
        alpha = x ** 3 + S256Field(B)
        beta = alpha.sqrt()
        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = S256Field(P - beta.num)
        else:
            even_beta = S256Field(P - beta.num)
            odd_beta = beta
        if is_even:
            return S256Point(x, even_beta)
        return S256Point(x, odd_beta)


G = S256Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


class S256PointTest(TestCase):
    def test_sec_uncompressed(self):
        from ecc.PrivateKey import PrivateKey

        priv = PrivateKey(5000)
        result = priv.point.sec(compressed=False).hex()
        self.assertEqual(
            result,
            "04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10",
        )

    def test_sec_compressed(self):
        from ecc.PrivateKey import PrivateKey

        priv = PrivateKey(5001)
        result = priv.point.sec(compressed=True).hex()
        self.assertEqual(
            result, "0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1"
        )

    def test_parse_uncompressed(self):
        from ecc.PrivateKey import PrivateKey

        priv = PrivateKey(5000)
        sec = priv.point.sec(compressed=False)
        result = S256Point.parse(sec)
        self.assertEqual(result, priv.point)

    def test_parse_compressed(self):
        from ecc.PrivateKey import PrivateKey

        priv = PrivateKey(5001)
        sec = priv.point.sec(compressed=True)
        result = S256Point.parse(sec)
        self.assertEqual(result, priv.point)

    def test_address_uncompressed_testnet(self):
        from ecc.PrivateKey import PrivateKey

        priv = PrivateKey(5002)
        result = priv.point.address(compressed=False, testnet=True)
        self.assertEqual(result, "mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA")

    def test_address_compressed_testnet(self):
        from ecc.PrivateKey import PrivateKey

        priv = PrivateKey(2020 ** 5)
        result = priv.point.address(compressed=True, testnet=True)
        self.assertEqual(result, "mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH")

    def test_address_compressed_mainnet(self):
        from ecc.PrivateKey import PrivateKey

        priv = PrivateKey(0x12345DEADBEEF)
        result = priv.point.address()
        self.assertEqual(result, "1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1")
