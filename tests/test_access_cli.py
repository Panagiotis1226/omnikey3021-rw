import io
import os
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout

from omnikey3021.access import AccessController, AccessStore, load_or_create_key
from omnikey3021.access.credential import BLOCK_SIZE, Credential, CredentialBlock, derive_card_key
from omnikey3021.cli import main
from omnikey3021.simulator import SimulatedIsoCard, SimulatedMemoryCard, SimulatedReader


class TestCredentialBlock(unittest.TestCase):
    def test_pack_verify(self):
        key = b"k" * 32
        cred = Credential(7, 1234, 1_700_000_000, 0, 2)
        block = CredentialBlock.pack(cred, key, b"binding")
        self.assertEqual(len(block), BLOCK_SIZE)
        self.assertTrue(CredentialBlock.verify(block, key, b"binding"))
        self.assertFalse(CredentialBlock.verify(block, key, b"other-card"))
        self.assertFalse(CredentialBlock.verify(block, b"x" * 32, b"binding"))
        parsed = CredentialBlock.parse(block)
        self.assertEqual((parsed.site_code, parsed.card_id, parsed.access_level), (7, 1234, 2))
        self.assertTrue(CredentialBlock.is_blank(b"\xff" * 64))
        self.assertTrue(CredentialBlock.is_blank(b"\x00" * 64))
        self.assertFalse(CredentialBlock.is_blank(block))
        tampered = bytearray(block)
        tampered[19] = 9  # raise access level
        self.assertFalse(CredentialBlock.verify(bytes(tampered), key, b"binding"))
        with self.assertRaises(ValueError):
            CredentialBlock.parse(b"\x00" * 64)


class TestAccessController(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.key = load_or_create_key(os.path.join(self.tmp, "site.key"))
        self.assertEqual(len(self.key), 32)
        self.store = AccessStore(os.path.join(self.tmp, "db.sqlite3"))
        self.ctl = AccessController(self.store, self.key, 42)
        self.holder = self.store.add_holder("Alice", 2)

    def tearDown(self):
        self.store.close()

    def test_memory_card_flow(self):
        card = SimulatedMemoryCard(psc=b"\xff\xff\xff")
        ch = SimulatedReader(card).connect()
        self.assertIn("blank", self.ctl.check(ch).reason)
        cred, rec = self.ctl.enroll(ch, self.holder, psc=b"\xff\xff\xff", expires=time.time() + 30 * 86400)
        self.assertEqual(rec.card_id, 1)
        d = self.ctl.check(ch)
        self.assertTrue(d.granted, d.reason)
        self.assertEqual(d.holder.name, "Alice")
        # expiry
        self.assertEqual(self.ctl.check(ch, when=time.time() + 31 * 86400).reason, "credential expired")
        # revoke / restore
        self.store.revoke_card(1)
        self.assertEqual(self.ctl.check(ch).reason, "card revoked")
        self.store.revoke_card(1, False)
        # holder disabled
        self.store.set_holder_active(self.holder.id, False)
        self.assertIn("holder", self.ctl.check(ch).reason)
        self.store.set_holder_active(self.holder.id, True)
        # schedule
        self.store.add_schedule(2, [0, 1, 2, 3, 4], 8 * 60, 18 * 60)
        monday_noon = time.mktime((2026, 9, 7, 12, 0, 0, 0, 0, -1))
        sunday_noon = time.mktime((2026, 9, 6, 12, 0, 0, 0, 0, -1))
        self.assertTrue(self.ctl.check(ch, when=monday_noon).granted)
        self.assertEqual(self.ctl.check(ch, when=sunday_noon).reason, "outside allowed schedule")
        # clone: same block on a different card fails the binding
        clone = SimulatedMemoryCard()
        clone.memory[32:96] = card.memory[32:96]
        d = self.ctl.check(SimulatedReader(clone).connect())
        self.assertFalse(d.granted)
        self.assertIn("signature", d.reason)
        # wrong site key
        other = AccessController(self.store, b"z" * 32, 42)
        self.assertIn("signature", other.check(ch).reason)
        # erase
        self.ctl.erase(ch, psc=b"\xff\xff\xff")
        self.assertIn("blank", self.ctl.check(ch).reason)
        self.assertGreater(len(self.store.events()), 5)

    def test_iso_card_flow_with_challenge(self):
        card = SimulatedIsoCard()
        ch = SimulatedReader(card).connect()
        ctl = AccessController(self.store, self.key, 42, iso_pin=b"1234", iso_challenge=True)
        cred, rec = ctl.enroll(ch, self.holder)
        self.assertEqual(rec.kind, "iso7816")
        # card key not provisioned -> challenge fails
        self.assertEqual(ctl.check(ch).reason, "challenge/response failed")
        card.auth_key = derive_card_key(self.key, cred.card_id)
        self.assertTrue(ctl.check(ch).granted)
        # without challenge requirement the block alone is enough
        plain = AccessController(self.store, self.key, 42)
        self.assertTrue(plain.check(ch).granted)

    def test_wrong_site_code(self):
        ch = SimulatedReader(SimulatedMemoryCard()).connect()
        other_site = AccessController(self.store, self.key, 99)
        other_site.enroll(ch, self.holder, psc=b"\xff\xff\xff")
        self.assertIn("site code", self.ctl.check(ch).reason)


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state = os.path.join(self.tmp, "sim.state")
        self.db = os.path.join(self.tmp, "acc.sqlite3")
        self.keyf = os.path.join(self.tmp, "acc.key")

    def run_cli(self, *argv, sim="sle4442"):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["--simulate", sim, "--sim-state", self.state, *argv])
        return rc, out.getvalue(), err.getvalue()

    def test_info_and_memory_commands(self):
        rc, out, _ = self.run_cli("info")
        self.assertEqual(rc, 0)
        self.assertIn("SLE4432/SLE4442", out)
        self.assertIn("productName", out)
        rc, out, _ = self.run_cli("mem", "verify", "FFFFFF")
        self.assertEqual(rc, 0)
        rc, out, _ = self.run_cli("mem", "write", "--addr", "64", "--psc", "FFFFFF", "--verify", "str:hi")
        self.assertEqual(rc, 0)
        rc, out, _ = self.run_cli("mem", "read", "--addr", "64", "--length", "2")
        self.assertIn("68 69", out)
        rc, out, _ = self.run_cli("mem", "protection")
        self.assertIn("8 of 32", out)
        rc, out, _ = self.run_cli("mem", "protect", "--addr", "20")
        self.assertEqual(rc, 2)  # needs --yes
        rc, out, _ = self.run_cli("mem", "verify", "000000")
        self.assertEqual(rc, 2)
        rc, out, _ = self.run_cli("reader", "slot", "--voltage", "5V,3V,1.8V")
        self.assertIn("0x1B", out)
        rc, out, _ = self.run_cli("reader", "eeprom", "0", "--data", "0102")
        self.assertEqual(rc, 0)
        rc, out, _ = self.run_cli("reader", "eeprom", "0", "2")
        self.assertIn("01 02", out)
        rc, out, _ = self.run_cli("atr", "3B", "04", "A2", "13", "10", "91")
        self.assertIn("SLE4432", out)

    def test_iso_commands(self):
        rc, out, _ = self.run_cli("iso", "select", "--fid", "0002", sim="iso-t0")
        self.assertIn("transparent EF", out)
        rc, out, _ = self.run_cli("iso", "read", "--fid", "0002", "--length", "16", sim="iso-t0")
        self.assertIn("hello ISO 7816", out)
        rc, out, _ = self.run_cli("iso", "write", "--fid", "0002", "--pin", "1234", "--verify", "str:ABC", sim="iso")
        self.assertEqual(rc, 0)
        self.assertIn("OK", out)
        rc, out, _ = self.run_cli("apdu", "00 A4 04 00 08 A000000003021001", sim="iso")
        self.assertIn("SW 9000", out)
        rc, out, _ = self.run_cli("apdu", "00 A4 00 00 02 99 99", sim="iso")
        self.assertEqual(rc, 2)
        self.assertIn("6A82", out)
        script = os.path.join(self.tmp, "s.apdu")
        with open(script, "w") as fh:
            fh.write("# test\nexpect 9000\n00 A4 04 00 08 A000000003021001\nexpect 6A82\n00A400000299 99\n")
        rc, out, _ = self.run_cli("script", script, sim="iso")
        self.assertEqual(rc, 0)

    def test_access_flow(self):
        common = ["--db", self.db, "--key-file", self.keyf]
        rc, out, _ = self.run_cli("access", "init", "--site-code", "7", *common)
        self.assertEqual(rc, 0)
        rc, out, _ = self.run_cli("access", "holder", "add", "Peter", "--level", "2", *common)
        self.assertIn("holder #1", out)
        rc, out, _ = self.run_cli("access", "check", *common)
        self.assertEqual(rc, 3)
        rc, out, _ = self.run_cli("access", "enroll", "--holder", "Peter", "--psc", "FFFFFF", *common)
        self.assertEqual(rc, 0, out)
        rc, out, _ = self.run_cli("access", "check", *common)
        self.assertEqual(rc, 0)
        self.assertIn("GRANTED", out)
        rc, out, _ = self.run_cli("access", "monitor", "--exec", "true", *common)
        self.assertEqual(rc, 0)
        rc, out, _ = self.run_cli("access", "revoke", "1", *common)
        rc, out, _ = self.run_cli("access", "check", *common)
        self.assertIn("revoked", out)
        rc, out, _ = self.run_cli("access", "cards", *common)
        self.assertIn("REVOKED", out)
        rc, out, _ = self.run_cli("access", "log", *common)
        self.assertIn("card revoked", out)
        rc, out, _ = self.run_cli("access", "schedule", "add", "--level", "2", "--days", "mon-fri",
                                  "--start", "08:00", "--end", "18:00", *common)
        rc, out, _ = self.run_cli("access", "schedule", "list", *common)
        self.assertIn("fri 08:00-18:00", out)
        rc, out, _ = self.run_cli("access", "erase", "--psc", "FFFFFF", *common)
        self.assertEqual(rc, 0)

    def test_no_card(self):
        rc, out, err = self.run_cli("mem", "info", sim="empty")
        self.assertEqual(rc, 4)
        rc, out, err = self.run_cli("reader", "caps", sim="empty")
        self.assertEqual(rc, 0)
        self.assertIn("HID Global", out)


if __name__ == "__main__":
    unittest.main()
