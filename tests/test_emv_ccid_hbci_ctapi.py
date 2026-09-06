import os
import struct
import tempfile
import unittest

from omnikey3021 import pcsc_constants as C
from omnikey3021.atr import parse_atr
from omnikey3021.ccid import (
    CCID_DESCRIPTOR_LENGTH, find_class_descriptor, find_usb_ccid_devices, parse_class_descriptor, parse_tlv_properties,
)
from omnikey3021.ctapi import CT, HOST, ICC1, OK, ERR_INVALID, ERR_TRANS, PcscCtApi, ct_bcs, request_icc_and_reset
from omnikey3021.emv import (
    EmvCard, TerminalData, decode_aip, decode_cvm_list, decode_date, decode_pan, decode_track2, parse_dol,
)
from omnikey3021.errors import CardError, UnsupportedCardError
from omnikey3021.hbci import AID_DDV_TYPE0, BankData, DDVCard
from omnikey3021.iso7816 import (
    CRT_DIGITAL_SIGNATURE, MSE_SET_COMPUTATION, PSO_COMPUTE_DIGITAL_SIGNATURE, Iso7816CardExtended,
)
from omnikey3021.pcsc import CardMonitor, ReaderState
from omnikey3021.simulator import (
    SimulatedDDVCard, SimulatedEmvCard, SimulatedIsoCard, SimulatedMemoryCard, SimulatedReader,
)


class TestEmvDecoders(unittest.TestCase):
    def test_basics(self):
        self.assertEqual(decode_pan(bytes.fromhex("4111111111111111")), "4111111111111111")
        self.assertEqual(decode_pan(bytes.fromhex("541333000000001F")), "541333000000001")
        self.assertEqual(decode_date(bytes.fromhex("281200")), "2028-12-31")
        self.assertEqual(decode_date(bytes.fromhex("260215")), "2026-02-15")
        t2 = decode_track2(bytes.fromhex("4111111111111111D2812201123456789F"))
        self.assertEqual(t2["pan"], "4111111111111111")
        self.assertEqual(t2["expiry"], "2028-12")
        self.assertEqual(t2["service_code"], "201")
        self.assertIn("DDA supported", decode_aip(b"\x20\x00"))
        cvm = decode_cvm_list(bytes.fromhex("000000000000000042031E031F00"))
        self.assertEqual(len(cvm), 4)
        self.assertIn("Enciphered PIN online", cvm[1])
        self.assertEqual(parse_dol(bytes.fromhex("9F66049F02069F3704")), [(0x9F66, 4), (0x9F02, 6), (0x9F37, 4)])

    def test_terminal_data(self):
        term = TerminalData(country_code=0x0276, currency_code=0x0978, amount=1250, unpredictable_number=b"\x01\x02\x03\x04")
        data = term.build_dol_data(bytes.fromhex("9F1A025F2A029F02069F3704"))
        self.assertEqual(data.hex().upper(), "02760978" + "000000001250" + "01020304")

    def test_atr_emv_compliance(self):
        ok = parse_atr(bytes.fromhex("3B6800000073C84013009000"))
        self.assertEqual(ok.emv_compliance(), [])
        # T=1 card that is fine for EMV: TA1 default, TB1=00, TD1=81 (T=1), TD2=31 (T=1) TA3=FE TB3=45 TC3 absent
        body = bytes.fromhex("F81300FF8131FE45") + b"\x80\x73\xc8\x21\x10" + b"\x00\x00\x00"
        raw = b"\x3b" + body
        tck = 0
        for b in body:
            tck ^= b
        good = parse_atr(raw + bytes([tck]))
        self.assertEqual(good.emv_compliance(), [], good.describe())
        bad = parse_atr(bytes.fromhex("3B9F958131FE9F006A31FE0A2E5A5C82FF"))  # no TB1, TA1=95, TA3 FE
        issues = bad.emv_compliance()
        self.assertTrue(any("TB1" in i for i in issues))
        self.assertTrue(any("TA1" in i for i in issues))
        self.assertEqual(parse_atr(bytes.fromhex("3B04A2131091")).emv_compliance(), ["not an asynchronous ISO 7816-3 card"])


class TestEmvCard(unittest.TestCase):
    def setUp(self):
        self.reader = SimulatedReader(SimulatedEmvCard())
        self.ch = self.reader.connect()
        self.emv = EmvCard(self.ch, TerminalData(country_code=0x0276, currency_code=0x0978))

    def test_full_read(self):
        apps = self.emv.list_applications()
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0].scheme, "Visa Credit/Debit")
        self.assertEqual(apps[0].priority, 1)
        data = self.emv.read_application(apps[0])
        self.assertEqual(data.pan, "4111111111111111")
        self.assertEqual(data.masked_pan(), "411111******1111")
        self.assertEqual(data.expiry, "2028-12-31")
        self.assertEqual(data.cardholder_name, "SIM CARDHOLDER/EMV")
        self.assertEqual(data.aip, b"\x1c\x00")
        self.assertEqual(len(data.records), 2)
        self.assertTrue(data.records[0].used_for_offline_auth is False)
        self.assertIn(0x8E, data.tags)
        self.assertEqual(self.emv.transaction_counter(), 42)
        self.assertEqual(self.emv.pin_try_counter(), 3)
        self.assertEqual(self.emv.last_online_atc(), 40)
        log = self.emv.transaction_log()
        self.assertEqual(len(log), 2)
        self.assertEqual(log[0]["Transaction Date"], "2026-09-01")
        # GPO was sent with a 14-byte PDOL payload under CLA 80
        gpo = [c for c, _ in self.ch.log if c[:2] == b"\x80\xa8"][0]
        self.assertEqual(gpo[4], 16)
        self.assertEqual(gpo[5:7], b"\x83\x0e")
        desc = "\n".join(data.describe())
        self.assertIn("411111******1111", desc)
        self.assertNotIn("4111111111111111", desc)
        self.assertIn("4111111111111111", "\n".join(data.describe(mask_pan=False)))

    def test_probe_fallback(self):
        card = self.reader.card
        original = card.process

        def no_pse(apdu):
            if apdu[:4] == b"\x00\xa4\x04\x00" and b"1PAY" in apdu:
                return b"\x6a\x82"
            return original(apdu)

        card.process = no_pse
        apps = self.emv.list_applications()
        self.assertEqual([a.aid for a in apps], [SimulatedEmvCard.AID])
        self.assertEqual(self.emv.list_applications(probe=False), [])


class TestCcid(unittest.TestCase):
    DESCRIPTOR = struct.pack(
        "<BBHBBIIIBIIBIIIIIBBHBB", CCID_DESCRIPTOR_LENGTH, 0x21, 0x0110, 0, 0x07, 0x03, 4000, 8000, 0, 10752, 344086, 0,
        254, 0x07, 0, 0x000400FE | 0x00040000, 271, 0xFF, 0xFF, 0, 0, 1)

    def test_parse_descriptor(self):
        d = parse_class_descriptor(self.DESCRIPTOR)
        self.assertEqual(d.version, "1.10")
        self.assertEqual(d.voltages, ["5.0V", "3.0V", "1.8V"])
        self.assertEqual(d.protocol_names, ["T=0", "T=1"])
        self.assertEqual(d.synchronous_protocols, ["2-wire (SLE 4432/4442)", "3-wire (SLE 4418/4428)", "I2C"])
        self.assertEqual(d.exchange_level, "short + extended APDU")
        self.assertEqual(d.max_ifsd, 254)
        self.assertIn("Automatic ICC voltage selection", d.feature_names)
        info = d.describe()
        self.assertIn("none (class 1 reader)", info["PIN pad"])
        with self.assertRaises(ValueError):
            parse_class_descriptor(b"\x00" * 10)

    def test_find_in_blob_and_sysfs(self):
        device = bytes([18, 1]) + b"\x00" * 16
        config = bytes([9, 2]) + b"\x00" * 7
        interface = bytes([9, 4, 0, 0, 3, 0x0B, 0, 0, 0])
        blob = device + config + interface + self.DESCRIPTOR + bytes([7, 5]) + b"\x00" * 5
        self.assertEqual(find_class_descriptor(blob), self.DESCRIPTOR)
        self.assertIsNone(find_class_descriptor(device + config))
        root = tempfile.mkdtemp()
        dev = os.path.join(root, "1-2")
        os.makedirs(os.path.join(root, "1-2:1.0"))
        os.makedirs(dev)
        for name, value in (("idVendor", "076b"), ("idProduct", "3021"), ("manufacturer", "HID Global"),
                            ("product", "OMNIKEY 3021"), ("serial", "OKCM0001"), ("bcdDevice", "0110"), ("version", " 2.00"),
                            ("speed", "12")):
            with open(os.path.join(dev, name), "w") as fh:
                fh.write(value + "\n")
        with open(os.path.join(dev, "descriptors"), "wb") as fh:
            fh.write(blob)
        with open(os.path.join(root, "1-2:1.0", "bInterfaceClass"), "w") as fh:
            fh.write("0b\n")
        os.makedirs(os.path.join(root, "1-3"))
        with open(os.path.join(root, "1-3", "idVendor"), "w") as fh:
            fh.write("1d6b\n")
        with open(os.path.join(root, "1-3", "idProduct"), "w") as fh:
            fh.write("0002\n")
        devs = find_usb_ccid_devices(sysfs_root=root)
        self.assertEqual(len(devs), 1)
        self.assertTrue(devs[0].is_omnikey)
        self.assertEqual(devs[0].model, "OMNIKEY 3021")
        self.assertEqual(devs[0].serial, "OKCM0001")
        self.assertEqual(devs[0].descriptor.max_ifsd, 254)
        self.assertEqual(find_usb_ccid_devices(vendor_id=0x1234, sysfs_root=root), [])

    def test_tlv_properties(self):
        raw = bytes.fromhex("0B026B07" "0C022130" "080A") + b"OK3021v1.0" + bytes.fromhex("0A04FFFF0000" "090100")
        props = parse_tlv_properties(raw)
        self.assertEqual(props["wIdVendor"], "076B")
        self.assertEqual(props["wIdProduct"], "3021")
        self.assertEqual(props["sFirmwareID"], "OK3021v1.0")
        self.assertEqual(props["dwMaxAPDUDataSize"], 65535)
        self.assertEqual(props["bPPDUSupport"], 0)


class TestHbci(unittest.TestCase):
    def setUp(self):
        self.card = SimulatedDDVCard(pin="12345")
        self.reader = SimulatedReader(self.card)
        self.ch = self.reader.connect()
        self.ddv = DDVCard(self.ch)

    def test_select_and_read(self):
        self.assertEqual(self.ddv.select(), 0)
        sent = [c for c, _ in self.ch.log if c[1] == 0xA4]
        self.assertEqual(sent[0][:5], bytes.fromhex("00A4040C09"))  # type 1 tried first
        self.assertEqual(sent[1][5:], AID_DDV_TYPE0)
        self.assertEqual(self.ddv.card_id_digits(), "6720123456789012")
        banks = self.ddv.all_bank_data()
        self.assertEqual(len(banks), 1)
        self.assertEqual(banks[0].blz, "12030000")
        self.assertEqual(banks[0].user_id, "USER0001")
        self.assertEqual(banks[0].comm_addr, "hbci.simbank.example.com")
        self.assertEqual(banks[0].country, "280")
        keys = self.ddv.key_data()
        self.assertEqual([(k.num, k.version) for k in keys], [(2, 7), (3, 5)])
        self.assertEqual(self.ddv.signature_counter(), 42)
        # the READ RECORD for EF_ID used SFI addressing: P1=01, P2=(19<<3)|4 = CC
        self.assertIn(bytes.fromhex("00B201CC00"), [c for c, _ in self.ch.log])

    def test_pin_block_and_verify(self):
        self.assertEqual(DDVCard.pin_block("12345").hex().upper(), "2512345FFFFFFFFF")
        self.assertEqual(DDVCard.pin_block("1234").hex().upper(), "241234FFFFFFFFFF")
        with self.assertRaises(ValueError):
            DDVCard.pin_block("12a")
        self.ddv.select()
        self.assertEqual(self.ddv.pin_tries_remaining(), 3)
        with self.assertRaises(CardError) as ctx:
            self.ddv.verify_pin("00000")
        self.assertEqual(ctx.exception.sw, 0x63C2)
        with self.assertRaises(CardError):
            self.ddv.set_signature_counter(1)  # needs PIN
        self.ddv.verify_pin("12345")
        self.assertEqual(self.ch.log[-1][0].hex().upper(), "00200081082512345FFFFFFFFF")
        self.ddv.set_signature_counter(43)
        self.assertEqual(self.ddv.signature_counter(), 43)

    def test_sign_and_keys(self):
        self.ddv.select()
        self.ddv.verify_pin("12345")
        h = bytes(range(20))
        mac = self.ddv.sign(h)
        self.assertEqual(len(mac), 8)
        self.assertEqual(bytes(self.card.mac_record), h[8:])
        self.assertEqual(self.card.put_data, h[:8])
        # type 0 MAC read uses CLA 04 READ RECORD P1 01 P2 DC
        self.assertIn(bytes.fromhex("04B201DC00"), [c for c, _ in self.ch.log])
        plain, enc = self.ddv.get_encryption_keys(3)
        self.assertEqual((len(plain), len(enc)), (16, 16))
        self.assertEqual(self.ddv.decrypt(3, enc), b"".join(self.card._mac(3, enc[i:i + 8]) for i in (0, 8)))
        with self.assertRaises(ValueError):
            self.ddv.sign(b"short")

    def test_bank_write_and_info(self):
        self.ddv.select()
        self.ddv.verify_pin("12345")
        self.ddv.write_bank_data(1, BankData(2, "SIM ING", "50010517", 2, "fints.example", "", "280", "KUNDE42"))
        banks = self.ddv.all_bank_data()
        self.assertEqual(banks[1].blz, "50010517")
        self.assertEqual(banks[1].user_id, "KUNDE42")
        info = self.ddv.info()
        self.assertEqual(info["card type"], "DDV type 0")
        self.assertIn("bank[2] BLZ", info)

    def test_not_a_ddv_card(self):
        with self.assertRaises(UnsupportedCardError):
            DDVCard(SimulatedReader(SimulatedIsoCard()).connect()).select()


class TestCtApi(unittest.TestCase):
    def setUp(self):
        self.reader = SimulatedReader(SimulatedIsoCard())
        self.api = PcscCtApi(reader_factory=lambda pn: self.reader)

    def test_ct_bcs_flow(self):
        self.assertEqual(self.api.CT_init(1, 0), OK)
        self.assertEqual(self.api.CT_init(1, 0), ERR_INVALID)
        rc, dad, sad, resp = self.api.CT_data(1, CT, HOST, ct_bcs(0x13, 0x00, 0x46, le=0))
        self.assertEqual((rc, dad, sad), (OK, HOST, CT))
        self.assertEqual(resp[0], 0x46)
        self.assertTrue(resp.endswith(b"\x90\x00"))
        self.assertIn(b"OMNIKEY 3021", resp)
        # status before connect: card present, not connected
        rc, _, _, resp = self.api.CT_data(1, CT, HOST, ct_bcs(0x13, 0x00, 0x80, le=0))
        self.assertEqual(resp, b"\x80\x01\x03\x90\x00")
        # REQUEST ICC with ATR -> async card 9001
        rc, _, _, resp = self.api.CT_data(1, CT, HOST, ct_bcs(0x12, 0x01, 0x01, b"\x0f", 0))
        self.assertEqual(resp[-2:], b"\x90\x01")
        self.assertEqual(resp[:-2], SimulatedIsoCard.atr)
        rc, _, _, resp = self.api.CT_data(1, CT, HOST, ct_bcs(0x13, 0x00, 0x80, le=0))
        self.assertEqual(resp, b"\x80\x01\x05\x90\x00")
        # ICC command
        rc, _, _, resp = self.api.CT_data(1, ICC1, HOST, bytes.fromhex("00A4040008A000000003021001"))
        self.assertEqual(rc, OK)
        self.assertEqual(resp[-2:], b"\x90\x00")
        # RESET ICC returning historical bytes
        rc, _, _, resp = self.api.CT_data(1, CT, HOST, ct_bcs(0x11, 0x01, 0x02, le=0))
        self.assertEqual(resp[-2:], b"\x90\x01")
        self.assertEqual(resp[:-2], parse_atr(SimulatedIsoCard.atr).historical)
        # keypad commands unsupported on a class 1 reader
        rc, _, _, resp = self.api.CT_data(1, CT, HOST, ct_bcs(0x18, 0x01, 0x00))
        self.assertEqual(resp, b"\x6d\x00")
        # eject
        rc, _, _, resp = self.api.CT_data(1, CT, HOST, ct_bcs(0x15, 0x01, 0x00))
        self.assertEqual(resp, b"\x90\x00")
        self.assertEqual(self.api.CT_data(1, 0x05, HOST, b"\x00")[0], ERR_INVALID)
        self.assertEqual(self.api.CT_data(9, CT, HOST, b"\x00")[0], ERR_INVALID)
        self.assertEqual(self.api.CT_close(1), OK)
        self.assertEqual(self.api.CT_close(1), ERR_INVALID)

    def test_memory_card_is_synchronous_and_no_card(self):
        self.reader.card = SimulatedMemoryCard()
        api = PcscCtApi(reader_factory=lambda pn: self.reader)
        atr = request_icc_and_reset(api, 1, 0)
        self.assertEqual(atr, SimulatedMemoryCard.atr)
        rc, _, _, resp = api.CT_data(1, CT, HOST, ct_bcs(0x11, 0x01, 0x00))
        self.assertEqual(resp, b"\x90\x00")  # synchronous ICC
        self.reader.remove()
        rc, _, _, resp = api.CT_data(1, CT, HOST, ct_bcs(0x11, 0x01, 0x00))
        self.assertEqual(resp, b"\x64\x00")
        rc, _, _, _ = api.CT_data(1, ICC1, HOST, b"\x00\xa4\x00\x00")
        self.assertEqual(rc, ERR_TRANS)


class TestIsoExtended(unittest.TestCase):
    def test_encodings(self):
        sent = []

        class Chan:
            atr = b""
            protocol = 1

            def transmit(self, d):
                sent.append(bytes(d))
                return b"\x90\x00"

            def control(self, c, d=b""):
                return b""

        iso = Iso7816CardExtended(Chan())
        iso.create_transparent_ef(0x0101, 128)
        self.assertEqual(sent[-1].hex().upper(), "00E000000D620B8002008082010183020101")
        iso.delete_file(0x0101)
        self.assertEqual(sent[-1].hex().upper(), "00E40000020101")
        iso.manage_security_environment(MSE_SET_COMPUTATION, CRT_DIGITAL_SIGNATURE, bytes.fromhex("840181800102"))
        self.assertEqual(sent[-1].hex().upper(), "002241B606840181800102")
        iso.compute_digital_signature(b"\x01" * 4)
        self.assertEqual(sent[-1].hex().upper(), "002A9E9A040101010100")
        self.assertEqual(PSO_COMPUTE_DIGITAL_SIGNATURE, (0x9E, 0x9A))
        iso.decipher(b"\xaa\xbb")
        self.assertEqual(sent[-1].hex().upper(), "002A80860300AABB00")
        iso.search_record(b"\x5a", 1, sfi=2)
        self.assertEqual(sent[-1].hex().upper(), "00A20114015A00")
        iso.get_data_odd(b"\x5c\x00")
        self.assertEqual(sent[-1].hex().upper(), "00CB3FFF025C0000")
        iso.general_authenticate(b"\x7c\x00")
        self.assertEqual(sent[-1].hex().upper(), "008600 00027C0000".replace(" ", ""))


class FakeContext:
    """Scripted SCardGetStatusChange for CardMonitor tests."""

    def __init__(self, script):
        self.script = list(script)
        self.readers = ["HID Global OMNIKEY 3x21 Smart Card Reader 00 00"]
        self.cancelled = False

    def list_readers(self):
        return self.readers

    def get_status_change(self, names, states, timeout):
        if not self.script:
            from omnikey3021.errors import PCSCError

            raise PCSCError(C.SCARD_E_CANCELLED, "SCardGetStatusChange")
        step = self.script.pop(0)
        out = []
        for n in names:
            if n in step:
                out.append(ReaderState(n, step[n][0], step[n][1]))
            else:
                out.append(ReaderState(n, states[names.index(n)], b""))
        return out

    def cancel(self):
        self.cancelled = True


class TestCardMonitor(unittest.TestCase):
    def test_events(self):
        name = "HID Global OMNIKEY 3x21 Smart Card Reader 00 00"
        atr = bytes.fromhex("3B04A2131091")
        script = [
            {name: (C.SCARD_STATE_EMPTY, b"")},                                          # initial: empty
            {name: (C.SCARD_STATE_CHANGED | C.SCARD_STATE_PRESENT, atr)},                # insert
            {name: (C.SCARD_STATE_CHANGED | C.SCARD_STATE_PRESENT | C.SCARD_STATE_INUSE, atr)},  # in use, no event
            {name: (C.SCARD_STATE_CHANGED | C.SCARD_STATE_EMPTY, b"")},                  # remove
        ]
        events = []
        mon = CardMonitor(lambda e, r, a: events.append((e, r, a)), [name], context=FakeContext(script), hotplug=False)
        mon.loop()
        self.assertEqual(events, [("insert", name, atr), ("remove", name, b"")])


if __name__ == "__main__":
    unittest.main()
