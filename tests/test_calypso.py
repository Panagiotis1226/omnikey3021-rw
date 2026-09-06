import unittest

from omnikey3021.calypso import (
    AID_1TIC_ICA, CalypsoCard, SFI_CONTRACTS, SFI_COUNTERS, SFI_ENVIRONMENT, StartupInfo, _parse_fci,
)
from omnikey3021.errors import CardError, CredentialError, UnsupportedCardError
from omnikey3021.simulator import SimulatedCalypsoCard, SimulatedIsoCard, SimulatedReader, SimulatedSam


class TestStartupAndFci(unittest.TestCase):
    def test_startup(self):
        si = StartupInfo.parse(bytes([0x1D, 0x04, 0x06, 0x00, 0x11, 0x02, 0x01]))
        self.assertEqual(si.buffer_size, 0x1D)
        self.assertEqual(si.describe()["platform"], "Calypso Prime Rev3.1")
        self.assertEqual(si.describe()["software version"], "2.1")

    def test_parse_fci(self):
        from omnikey3021.tlv import tlv

        fci = tlv(0x6F, None, tlv(0x84, AID_1TIC_ICA),
                  tlv(0xA5, None, tlv(0xBF0C, None, tlv(0xC7, bytes.fromhex("0102030405060708")),
                                      tlv(0x53, bytes([0x1D, 0x04, 0x06, 0, 0x11, 2, 1]))))).encode()
        serial, startup = _parse_fci(fci)
        self.assertEqual(serial.hex(), "0102030405060708")
        self.assertEqual(startup.platform, 0x04)


class TestCalypsoRead(unittest.TestCase):
    def setUp(self):
        self.key = b"\x02" * 16
        self.card_sim = SimulatedCalypsoCard(key=self.key)
        self.ch = SimulatedReader(self.card_sim).connect()
        self.card = CalypsoCard(self.ch)

    def test_select_and_read(self):
        ident = self.card.select_application()
        self.assertEqual(ident.aid, AID_1TIC_ICA)
        self.assertEqual(ident.serial_hex, "08201223C46D4A18")
        self.assertEqual(ident.startup.platform, 0x04)
        env = self.card.read_record(SFI_ENVIRONMENT, 1)
        self.assertEqual(env[0], 0x24)
        recs = self.card.read_records(0x08)
        self.assertEqual(len(recs), 3)
        # SELECT AID APDU shape (case 4, Le=00)
        first = self.ch.log[0][0]
        self.assertEqual(first[:5].hex().upper(), "00A4040008")
        self.assertEqual(first[-1], 0x00)
        # READ RECORDS P2 = (SFI<<3)|4
        read = [c for c, _ in self.ch.log if c[1] == 0xB2][0]
        self.assertEqual(read[3], (SFI_ENVIRONMENT << 3) | 0x04)

    def test_dump_and_info(self):
        self.card.select_application()
        dump = self.card.dump()
        self.assertEqual(set(dump), {0x07, 0x08, 0x09, 0x19})
        info = self.card.info()
        self.assertEqual(info["serial"], "08201223C46D4A18")

    def test_legacy_cla_fallback(self):
        # a card that only answers CLA 94 for SELECT
        sim = SimulatedCalypsoCard(key=self.key)
        original = sim.process

        def only_94(apdu):
            if apdu[:4] == b"\x00\xa4\x04\x00":
                return b"\x6e\x00"
            return original(apdu)

        sim.process = only_94
        card = CalypsoCard(SimulatedReader(sim).connect())
        ident = card.select_application()
        self.assertEqual(card.revision, 2)
        self.assertEqual(ident.serial_hex, "08201223C46D4A18")

    def test_not_calypso(self):
        card = CalypsoCard(SimulatedReader(SimulatedIsoCard()).connect())
        with self.assertRaises(UnsupportedCardError):
            card.select_application()


class TestCalypsoSecureSession(unittest.TestCase):
    def setUp(self):
        self.key = b"\x07" * 16
        self.card_sim = SimulatedCalypsoCard(key=self.key)
        self.ch = SimulatedReader(self.card_sim).connect()
        self.card = CalypsoCard(self.ch)
        self.card.select_application()

    def test_write_in_session_authenticated(self):
        sam = SimulatedSam(self.key)
        self.card.open_secure_session(sam, key_index=1)
        self.card.update_record(SFI_CONTRACTS, 1, b"\x02" + b"\xAB" * 28)
        newcnt = self.card.increase_counter(SFI_COUNTERS, 0, 5)
        self.assertTrue(self.card.close_secure_session())
        self.assertEqual(self.card_sim.files[SFI_CONTRACTS][0][:2], b"\x02\xAB")
        self.assertEqual(int.from_bytes(newcnt, "big"), 0x69)
        # OPEN SECURE SESSION APDU used INS 8A and carried the 8-byte terminal challenge
        opn = [c for c, _ in self.ch.log if c[1] == 0x8A][0]
        self.assertEqual(opn[4], 0x08)
        # CLOSE used INS 8E with P1 80 (ratify)
        cls = [c for c, _ in self.ch.log if c[1] == 0x8E][0]
        self.assertEqual(cls[2], 0x80)

    def test_wrong_key_rejected_by_card(self):
        sam = SimulatedSam(b"\x99" * 16)  # SAM with the wrong key
        self.card.open_secure_session(sam, key_index=1)
        self.card.update_record(SFI_CONTRACTS, 1, b"\x02" + b"\x00" * 28)
        with self.assertRaises(CardError) as ctx:
            self.card.close_secure_session()
        self.assertEqual(ctx.exception.sw, 0x6988)  # card refuses: terminal not authenticated

    def test_card_mac_verified_by_sam(self):
        # a card that returns a bad MAC must fail SAM authentication
        sam = SimulatedSam(self.key)
        self.card.open_secure_session(sam, key_index=1)
        self.card.update_record(SFI_CONTRACTS, 1, b"\x02" + b"\x11" * 28)
        orig = self.card_sim.process

        def bad_mac(apdu):
            resp = orig(apdu)
            if apdu[1] == 0x8E and resp.endswith(b"\x90\x00"):
                return b"\x00\x00\x00\x00\x90\x00"  # wrong card MAC
            return resp

        self.card_sim.process = bad_mac
        with self.assertRaises(CredentialError):
            self.card.close_secure_session()

    def test_write_without_session_refused(self):
        with self.assertRaises(CredentialError):
            self.card.update_record(SFI_CONTRACTS, 1, b"\x00" * 29)

    def test_pcsc_sam_apdus(self):
        from omnikey3021.calypso import PcscSam

        sent = []

        class SamChan:
            atr = b""
            protocol = 1

            def transmit(self, d):
                sent.append(bytes(d))
                if d[1] == 0x84:
                    return bytes(range(8)) + b"\x90\x00"
                if d[1] == 0x8E:
                    return b"\xAA\xBB\xCC\xDD\x90\x00"
                return b"\x90\x00"

            def control(self, c, d=b""):
                return b""

        sam = PcscSam(SamChan())
        sam.select_diversifier(bytes.fromhex("0102030405060708"))
        self.assertEqual(sent[-1].hex().upper(), "8014000008" + "0102030405060708")
        self.assertEqual(sam.get_challenge(), bytes(range(8)))
        sam.digest_init(1, b"\x01\x02")
        self.assertEqual(sent[-1].hex().upper(), "808A0001020102")
        sam.digest_update(b"\x00\xb2\x01\x3c\x00")
        self.assertEqual(sent[-1][:4].hex().upper(), "808C0000")
        self.assertEqual(sam.digest_close(), bytes.fromhex("AABBCCDD"))
        self.assertTrue(sam.digest_authenticate(bytes.fromhex("AABBCCDD")))


if __name__ == "__main__":
    unittest.main()
