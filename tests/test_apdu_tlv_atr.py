import unittest

from omnikey3021.apdu import CommandAPDU, ResponseAPDU, describe_sw, parse_hex, transmit_apdu
from omnikey3021.atr import CardKind, parse_atr
from omnikey3021.errors import CardError
from omnikey3021.tlv import decode, encode, encode_length, tlv


class TestCommandAPDU(unittest.TestCase):
    def test_cases(self):
        self.assertEqual(CommandAPDU(0x00, 0xA4, 0x04, 0x00).to_bytes(), bytes.fromhex("00A40400"))
        self.assertEqual(CommandAPDU(0x00, 0x84, 0, 0, le=8).to_bytes(), bytes.fromhex("0084000008"))
        self.assertEqual(CommandAPDU(0x00, 0xB0, 0, 0, le=256).to_bytes(), bytes.fromhex("00B0000000"))
        self.assertEqual(CommandAPDU(0xFF, 0x20, 0, 0, b"\x01\x02\x03").to_bytes(), bytes.fromhex("FF20000003010203"))
        self.assertEqual(CommandAPDU(0x00, 0xA4, 4, 0, b"\xa0\x00", le=256).to_bytes(), bytes.fromhex("00A4040002A00000"))

    def test_extended(self):
        data = bytes(300)
        cmd = CommandAPDU(0x00, 0xD6, 0, 0, data)
        self.assertTrue(cmd.extended)
        raw = cmd.to_bytes()
        self.assertEqual(raw[4:7], b"\x00\x01\x2c")
        self.assertEqual(len(raw), 7 + 300)
        cmd = CommandAPDU(0x00, 0xB0, 0, 0, le=1000)
        self.assertEqual(cmd.to_bytes(), bytes.fromhex("00B000000003E8"))
        cmd = CommandAPDU(0x00, 0xCA, 0, 0, b"\x01", le=65536, extended=True)
        self.assertEqual(cmd.to_bytes(), bytes.fromhex("00CA0000000001010000"))

    def test_parse_roundtrip(self):
        for hexs in ["00A40400", "0084000008", "FF20000003010203", "00A4040002A00000", "00B000000003E8",
                     "00D6000000012C" + "00" * 300, "00CA0000000001010000"]:
            raw = bytes.fromhex(hexs)
            self.assertEqual(CommandAPDU.parse(raw).to_bytes(), raw, hexs)

    def test_parse_hex(self):
        self.assertEqual(parse_hex("FF B0 00 00 10"), bytes.fromhex("FFB0000010"))
        self.assertEqual(parse_hex("0xFF,0xB0"), b"\xff\xb0")
        self.assertEqual(parse_hex("ff:b0"), b"\xff\xb0")
        with self.assertRaises(ValueError):
            parse_hex("FFB")


class TestResponse(unittest.TestCase):
    def test_sw(self):
        r = ResponseAPDU.from_bytes(bytes.fromhex("01029000"))
        self.assertTrue(r.ok)
        self.assertEqual(r.data, b"\x01\x02")
        self.assertEqual(describe_sw(0x63, 0xC2), "Verification failed; 2 retries remaining")
        self.assertIn("6C", describe_sw(0x6C, 0x10).replace("Wrong Le; exact length is 16", "6C"))
        self.assertIn("Security status", describe_sw(0x69, 0x82))
        with self.assertRaises(CardError) as ctx:
            ResponseAPDU.from_bytes(b"\x6a\x82").check(b"\x00\xa4")
        self.assertEqual(ctx.exception.sw, 0x6A82)

    def test_t0_conveniences(self):
        script = {
            bytes.fromhex("00CA9F7F00"): bytes.fromhex("6C08"),
            bytes.fromhex("00CA9F7F08"): bytes.fromhex("01020304050607089000"),
            bytes.fromhex("00A4040000"): bytes.fromhex("6104"),
            bytes.fromhex("00C0000004"): bytes.fromhex("6F02840090 00".replace(" ", "")),
        }
        sent = []

        def tx(b):
            sent.append(b)
            return script[b]

        r = transmit_apdu(tx, bytes.fromhex("00CA9F7F00"))
        self.assertEqual(r.data, bytes(range(1, 9)))
        r = transmit_apdu(tx, bytes.fromhex("00A4040000"))
        self.assertEqual(r.data, bytes.fromhex("6F028400"))
        self.assertTrue(r.ok)
        self.assertEqual(sent[-1], bytes.fromhex("00C0000004"))


class TestEmptyResponseFallback(unittest.TestCase):
    def test_case4_empty_then_case3_get_response(self):
        from omnikey3021.errors import OmnikeyError

        sent = []
        fci = bytes.fromhex("6F0A840831544943 2E494341".replace(" ", ""))

        def tx(b):
            sent.append(b)
            if b == bytes.fromhex("00A4040008315449432E49434100"):
                return b""                         # driver swallowed the case-4 response
            if b == bytes.fromhex("00A4040008315449432E494341"):
                return b"\x90\x00"                 # case 3 accepted
            if b == bytes.fromhex("00C0000000"):
                return fci + b"\x90\x00"
            return b"\x6d\x00"

        r = transmit_apdu(tx, bytes.fromhex("00A4040008315449432E49434100"))
        self.assertEqual(r.data, fci)
        self.assertEqual(len(sent), 3)
        with self.assertRaises(OmnikeyError):
            transmit_apdu(lambda b: b"", bytes.fromhex("00B0000010"))


class TestTLV(unittest.TestCase):
    def test_encode_decode(self):
        t = tlv(0xA2, None, tlv(0xA0, None, tlv(0xA0, None, tlv(0x82))))
        self.assertEqual(t.encode().hex().upper(), "A206A004A0028200")
        back = decode(t.encode())[0]
        self.assertEqual(back.tag, 0xA2)
        self.assertEqual(back.find_deep(0x82).value, b"")
        self.assertEqual(encode_length(0x7F), b"\x7f")
        self.assertEqual(encode_length(0x80), b"\x81\x80")
        self.assertEqual(encode_length(0x1234), b"\x82\x12\x34")
        self.assertEqual(encode(0x9F7F, b"\x01"), b"\x9f\x7f\x01\x01")
        items = decode(bytes.fromhex("9F7F0101" + "8102ABCD"))
        self.assertEqual([i.tag for i in items], [0x9F7F, 0x81])

    def test_truncated(self):
        with self.assertRaises(ValueError):
            decode(bytes.fromhex("A205A003"))


class TestATR(unittest.TestCase):
    def test_memory_card_pseudo_atr(self):
        atr = parse_atr(bytes.fromhex("3B04A2131091"))
        self.assertEqual(atr.kind, CardKind.SLE4442)
        self.assertTrue(atr.is_memory_card)
        atr = parse_atr(bytes.fromhex("92231091"))
        self.assertEqual(atr.kind, CardKind.SLE4428)

    def test_cpu_card(self):
        # Real-world style ATR: T=1, TA1=0x18, class A/B indicator via T=15
        body = bytes.fromhex("D518FF8191FE1FC38073C82110")
        tck = 0
        for b in body:
            tck ^= b
        atr = parse_atr(b"\x3b" + body + bytes([tck]))
        self.assertEqual(atr.kind, CardKind.ASYNC)
        self.assertEqual(atr.protocols, [1])
        self.assertTrue(atr.supports_t1)
        self.assertFalse(atr.supports_t0)
        self.assertEqual(atr.fi, 372)
        self.assertEqual(atr.di, 12)
        self.assertTrue(atr.tck_valid)
        self.assertIn("A/B", atr.class_indicator)
        self.assertEqual(atr.t1_parameters["IFSC"], 0xFE)
        self.assertEqual(atr.historical, bytes.fromhex("8073C82110"))
        self.assertEqual(atr.warnings, [])

    def test_t0_only(self):
        atr = parse_atr(bytes.fromhex("3B6500002063CB6800"))
        self.assertEqual(atr.protocols, [0])
        self.assertTrue(atr.supports_t0)
        self.assertEqual(len(atr.historical), 5)
        self.assertIsNone(atr.tck)

    def test_junk(self):
        atr = parse_atr(b"\x12\x34")
        self.assertEqual(atr.kind, CardKind.UNKNOWN_SYNC)
        self.assertTrue(atr.warnings)
        self.assertEqual(parse_atr(b"").kind, CardKind.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
