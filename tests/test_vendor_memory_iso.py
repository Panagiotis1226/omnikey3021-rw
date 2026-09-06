import unittest

from omnikey3021 import pcsc_constants as C
from omnikey3021.errors import CardError, UnsupportedCardError, VendorError
from omnikey3021.iso7816 import Iso7816Card
from omnikey3021.memorycard import I2CCard, SLE4428Card, SLE4442Card, open_memory_card
from omnikey3021.simulator import SimulatedIsoCard, SimulatedMemoryCard, SimulatedReader
from omnikey3021.tlv import tlv
from omnikey3021.vendor import (
    ReaderConfig, build_vendor_apdu, decode_voltage_sequence, encode_voltage_sequence, sync_2wbp, vendor_command,
)


class TestVendorEncoding(unittest.TestCase):
    """Byte-exact checks against the examples printed in HID PLT-03099."""

    def test_guide_examples(self):
        get_name = build_vendor_apdu(tlv(0xA2, None, tlv(0xA0, None, tlv(0xA0, None, tlv(0x82)))))
        self.assertEqual(get_name.hex().upper(), "FF70076B08A206A004A002820000")
        set_lvl = build_vendor_apdu(tlv(0xA2, None, tlv(0xA1, None, tlv(0xA3, None, tlv(0xA0, None, tlv(0x80, 0x02))))))
        self.assertEqual(set_lvl.hex().upper(), "FF70076B0BA209A107A305A00380010200")
        get_lvl = build_vendor_apdu(tlv(0xA2, None, tlv(0xA0, None, tlv(0xA3, None, tlv(0xA0, None, tlv(0x80))))))
        self.assertEqual(get_lvl.hex().upper(), "FF70076B0AA208A006A304A002800000")
        eeprom_w = build_vendor_apdu(tlv(0xA2, None, tlv(0xA1, None, tlv(0xA7, None, tlv(0x81, b"\x00\x00"),
                                                                             tlv(0x83, bytes([1, 2, 3, 4, 5]))))))
        self.assertEqual(eeprom_w.hex().upper(), "FF70076B11A20FA10DA70B81020000830501020304050000"[:-2])
        eeprom_r = build_vendor_apdu(tlv(0xA2, None, tlv(0xA0, None, tlv(0xA7, None, tlv(0x81, b"\x00\x00"), tlv(0x82, 5)))))
        self.assertEqual(eeprom_r.hex().upper(), "FF70076B0DA20BA009A7078102000082010500")
        reboot = build_vendor_apdu(tlv(0xA2, None, tlv(0xA1, None, tlv(0xA9, None, tlv(0x80, 0)))))
        self.assertEqual(reboot.hex().upper(), "FF70076B09A207A105A90380010000")
        w2 = build_vendor_apdu(tlv(0xA6, None, tlv(0xA0, bytes([0x38, 0xAA, 0x55]))))
        self.assertEqual(w2.hex().upper(), "FF70076B07A605A00338AA5500")
        i2c = build_vendor_apdu(tlv(0xA6, None, tlv(0xA2, bytes.fromhex("0310A10100"))))
        self.assertEqual(i2c.hex().upper(), "FF70076B09A607A2050310A1010000")

    def test_voltage_sequence(self):
        self.assertEqual(encode_voltage_sequence(["5V", "3V", "1.8V"]), 0x1B)
        self.assertEqual(encode_voltage_sequence(["1.8V", "3V", "5V"]), 0x39)
        self.assertEqual(encode_voltage_sequence(None), 0)
        self.assertEqual(decode_voltage_sequence(0x1B), ["5V", "3V", "1.8V"])
        self.assertEqual(decode_voltage_sequence(0), [])
        with self.assertRaises(ValueError):
            encode_voltage_sequence(["9V"])


class TestReaderConfig(unittest.TestCase):
    def setUp(self):
        self.reader = SimulatedReader(SimulatedMemoryCard())
        self.ch = self.reader.connect()
        self.cfg = ReaderConfig(self.ch)

    def test_capabilities(self):
        caps = self.cfg.capabilities()
        self.assertEqual(caps["productName"], "3021")
        self.assertEqual(caps["firmwareVersion"], "1.0.1")
        self.assertEqual(caps["sizeOfUserEEProm"], 1024)
        with self.assertRaises(VendorError):
            self.cfg.get_capability_raw(0x77)

    def test_slot_and_eeprom(self):
        self.cfg.set_voltage_sequence(0x1B)
        self.assertEqual(self.cfg.get_voltage_sequence(), 0x1B)
        self.cfg.set_operating_mode(1)
        self.assertEqual(self.cfg.get_operating_mode(), 1)
        self.cfg.set_exchange_level(4)
        self.assertIn("Extended", self.cfg.slot_configuration()["exchangeLevel"])
        self.cfg.write_eeprom(10, b"hello")
        self.assertEqual(self.cfg.read_eeprom(10, 5), b"hello")
        self.cfg.reboot()
        self.cfg.restore_factory_defaults()
        self.assertEqual(self.reader.firmware.rebooted, 1)
        self.assertEqual(self.cfg.get_exchange_level(), 2)
        with self.assertRaises(ValueError):
            self.cfg.set_exchange_level(9)

    def test_escape_path_without_card(self):
        reader = SimulatedReader(None)
        ch = reader.connect_direct()
        cfg = ReaderConfig(ch, via_control=True)
        self.assertEqual(cfg.get_capability(0x8F), "HID Global")
        feats = ch.features()
        self.assertEqual(feats[C.FEATURE_CCID_ESC_COMMAND].control_code, C.IOCTL_CCID_ESCAPE)

    def test_error_response_parsing(self):
        with self.assertRaises(VendorError) as ctx:
            vendor_command(self.ch, tlv(0xBC, b"\x00"))
        self.assertEqual(ctx.exception.code, 0x03)


class TestSLE4442(unittest.TestCase):
    def setUp(self):
        self.card = SimulatedMemoryCard(psc=bytes.fromhex("123456"))
        self.reader = SimulatedReader(self.card)
        self.ch = self.reader.connect()
        self.mem = open_memory_card(self.ch)

    def test_detection(self):
        self.assertIsInstance(self.mem, SLE4442Card)
        self.assertIsInstance(open_memory_card(self.ch, "sle4428"), SLE4428Card)
        with self.assertRaises(ValueError):
            open_memory_card(self.ch, "bogus")

    def test_read_write_requires_psc(self):
        self.assertEqual(len(self.mem.dump()), 256)
        with self.assertRaises(CardError) as ctx:
            self.mem.write(40, b"abc")
        self.assertEqual(ctx.exception.sw, 0x6982)
        self.mem.verify_psc(bytes.fromhex("123456"))
        self.mem.write(40, b"abc", verify=True)
        self.assertEqual(self.mem.read(40, 3), b"abc")
        with self.assertRaises(ValueError):
            self.mem.write(250, b"toolong" * 2)

    def test_pc_sc_apdu_bytes(self):
        self.mem.read(0x10, 4)
        sent = self.ch.log[-1][0]
        self.assertEqual(sent.hex().upper(), "FFB0001004")
        self.mem.verify_psc(bytes.fromhex("123456"))
        self.assertEqual(self.ch.log[-1][0].hex().upper(), "FF20000003123456")
        self.mem.write(0x20, b"\x11\x22")
        self.assertEqual(self.ch.log[-1][0].hex().upper(), "FFD60020021122")
        self.mem.read_protection_bits(0, 32)
        self.assertEqual(self.ch.log[-1][0].hex().upper(), "FF3A000020")
        self.mem.change_psc(bytes.fromhex("123456"), bytes.fromhex("ABCDEF"))
        self.assertEqual(self.ch.log[-1][0].hex().upper(), "FF21000006123456ABCDEF")

    def test_error_counter(self):
        self.assertEqual(self.mem.tries_remaining(), 3)
        with self.assertRaises(CardError) as ctx:
            self.mem.verify_psc(b"\x00\x00\x00")
        self.assertEqual(ctx.exception.sw, 0x63C2)
        self.assertEqual(self.mem.tries_remaining(), 2)
        self.mem.verify_psc(bytes.fromhex("123456"))
        self.assertEqual(self.mem.tries_remaining(), 3)
        for _ in range(2):
            with self.assertRaises(CardError):
                self.mem.verify_psc(b"\x00\x00\x00")
        with self.assertRaises(CardError) as ctx:
            self.mem.verify_psc(b"\x00\x00\x00")
        self.assertEqual(ctx.exception.sw, 0x6983)  # blocked

    def test_protection(self):
        bits = self.mem.read_protection_bits(0, 32)
        self.assertEqual(bits[:8], [True] * 8)
        self.mem.verify_psc(bytes.fromhex("123456"))
        self.mem.write(20, b"\x5a")
        self.mem.protect(20, b"\x5a")
        self.assertTrue(self.mem.read_protection_bits(20, 1)[0])
        with self.assertRaises(CardError):
            self.mem.write(20, b"\x00")  # now frozen
        with self.assertRaises(CardError):
            self.mem.protect(21, b"\x00")  # content mismatch
        with self.assertRaises(ValueError):
            self.mem.read_protection_bits(30, 5)

    def test_raw_2wbp(self):
        data = sync_2wbp(self.ch, 0x30, 0x00, 0x00)
        self.assertEqual(data, bytes([self.card.memory[0]]))
        sec = self.mem.read_security_memory()
        self.assertEqual(sec[0], 0x07)
        self.assertEqual(sec[1:], b"\x00\x00\x00")  # PSC hidden until verified
        self.mem.verify_psc(bytes.fromhex("123456"))
        self.assertEqual(self.mem.read_security_memory()[1:], bytes.fromhex("123456"))

    def test_i2c_command_encoding(self):
        i2c = I2CCard(self.ch, "AT24C64")
        self.assertEqual(i2c.size, 8192)
        with self.assertRaises(CardError):  # simulated 2WBP card answers 6F00 to I2C commands
            i2c.init()
        self.assertEqual(self.ch.log[-1][0].hex().upper(), "FF3000040801142002" + "00002000")
        with self.assertRaises(ValueError):
            I2CCard(self.ch, "nonexistent")
        with self.assertRaises(ValueError):
            I2CCard(self.ch)


class TestIso7816(unittest.TestCase):
    def _run(self, t0_style):
        reader = SimulatedReader(SimulatedIsoCard(t0_style=t0_style))
        ch = reader.connect()
        iso = Iso7816Card(ch)
        fci = iso.select_mf()
        self.assertEqual(fci.fid, 0x3F00)
        fci = iso.select_fid(0x0002)
        self.assertEqual(fci.file_size, 300)
        self.assertEqual(fci.descriptor_text, "transparent EF")
        data = iso.read_binary()
        self.assertEqual(len(data), 300)
        self.assertEqual(iso.read_binary(6, 3), b"ISO")
        with self.assertRaises(CardError) as ctx:
            iso.update_binary(0, b"x")
        self.assertEqual(ctx.exception.sw, 0x6982)
        self.assertEqual(iso.verify_retries(), 3)
        with self.assertRaises(CardError):
            iso.verify("0000")
        self.assertEqual(iso.verify_retries(), 2)
        iso.verify("1234")
        iso.update_binary(0, b"XYZ")
        self.assertEqual(iso.read_binary(0, 3), b"XYZ")
        self.assertEqual(len(iso.get_challenge(16)), 16)
        self.assertEqual(len(iso.get_data(0x9F7F)), 8)
        fci = iso.select_aid(SimulatedIsoCard.AID)
        self.assertEqual(fci.df_name, SimulatedIsoCard.AID)
        with self.assertRaises(CardError) as ctx:
            iso.select_fid(0x9999)
        self.assertEqual(ctx.exception.sw, 0x6A82)
        iso.change_reference_data("1234", "4321")
        iso.verify("4321")
        return ch

    def test_t1(self):
        self._run(False)

    def test_t0_get_response_and_6c(self):
        ch = self._run(True)
        # make sure the T=0 conventions were actually exercised
        sws = [resp[-2] for _, resp in ch.log]
        self.assertIn(0x61, sws)
        self.assertIn(0x6C, sws)

    def test_unsupported_memory_open(self):
        reader = SimulatedReader(SimulatedIsoCard())
        with self.assertRaises(UnsupportedCardError):
            open_memory_card(reader.connect())


if __name__ == "__main__":
    unittest.main()
