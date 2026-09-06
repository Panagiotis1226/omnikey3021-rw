"""Extended tests for full Calypso read/write support.

Covers profile detection (Prime / Light / Basic), the high-level read helpers,
open sessions (read-only, no SAM), secure sessions (SAM-backed), all write
commands, the CalypsoSession context manager, and the error paths.
"""
import unittest

from omnikey3021.calypso import (
    AID_CALYPSO_BASIC, AID_CALYPSO_LIGHT, AID_CALYPSO_PRIME,
    CalypsoCard, CalypsoEF, CalypsoNoSamError, CalypsoProfile, CalypsoSession,
    CalypsoSessionError, CalypsoWriteError, EFType, KEY_DEBIT, KEY_RELOAD,
    SFI_CONTRACTS, SFI_COUNTERS, SFI_ENVIRONMENT, SFI_EVENT_LOG, STANDARD_EFS,
    StartupInfo, detect_profile,
)
from omnikey3021.errors import CardError
from omnikey3021.simulator import (
    SimulatedCalypsoCard, SimulatedReader, SimulatedSam,
)


# ---------------------------------------------------------------------------
# Profile detection
# ---------------------------------------------------------------------------
class TestProfileDetection(unittest.TestCase):
    def test_detect_by_aid(self):
        self.assertEqual(detect_profile(aid=AID_CALYPSO_PRIME), CalypsoProfile.PRIME)
        self.assertEqual(detect_profile(aid=AID_CALYPSO_LIGHT), CalypsoProfile.LIGHT)
        self.assertEqual(detect_profile(aid=AID_CALYPSO_BASIC), CalypsoProfile.BASIC)

    def test_detect_by_startup_platform(self):
        prime = StartupInfo.parse(SimulatedCalypsoCard.STARTUP_PRIME)
        light = StartupInfo.parse(SimulatedCalypsoCard.STARTUP_LIGHT)
        basic = StartupInfo.parse(SimulatedCalypsoCard.STARTUP_BASIC)
        self.assertEqual(detect_profile(startup=prime), CalypsoProfile.PRIME)
        self.assertEqual(detect_profile(startup=light), CalypsoProfile.LIGHT)
        self.assertEqual(detect_profile(startup=basic), CalypsoProfile.BASIC)

    def test_detect_unknown(self):
        self.assertEqual(detect_profile(), CalypsoProfile.UNKNOWN)

    def _profile_of(self, sim):
        card = CalypsoCard(SimulatedReader(sim).connect())
        card.select_application(sim.AID)
        return card.profile

    def test_card_sets_profile_prime(self):
        self.assertEqual(self._profile_of(SimulatedCalypsoCard()), CalypsoProfile.PRIME)

    def test_card_sets_profile_light(self):
        self.assertEqual(self._profile_of(SimulatedCalypsoCard.light()), CalypsoProfile.LIGHT)

    def test_card_sets_profile_basic(self):
        self.assertEqual(self._profile_of(SimulatedCalypsoCard.basic()), CalypsoProfile.BASIC)

    def test_auto_select_detects_profile(self):
        sim = SimulatedCalypsoCard.light()
        card = CalypsoCard(SimulatedReader(sim).connect())
        ident = card.auto_select()
        self.assertEqual(ident.aid, AID_CALYPSO_LIGHT)
        self.assertEqual(card.profile, CalypsoProfile.LIGHT)


# ---------------------------------------------------------------------------
# EF metadata
# ---------------------------------------------------------------------------
class TestEfMetadata(unittest.TestCase):
    def test_standard_efs(self):
        ef = STANDARD_EFS[SFI_CONTRACTS]
        self.assertIsInstance(ef, CalypsoEF)
        self.assertEqual(ef.sfi, SFI_CONTRACTS)
        self.assertEqual(ef.ef_type, EFType.LINEAR)
        self.assertIn("Contracts", ef.describe())

    def test_counters_ef_type(self):
        self.assertEqual(STANDARD_EFS[SFI_COUNTERS].ef_type, EFType.COUNTERS)
        self.assertEqual(STANDARD_EFS[SFI_EVENT_LOG].ef_type, EFType.CYCLIC)


# ---------------------------------------------------------------------------
# High-level reads (open access, no SAM)
# ---------------------------------------------------------------------------
class TestHighLevelReads(unittest.TestCase):
    def setUp(self):
        self.sim = SimulatedCalypsoCard()
        self.card = CalypsoCard(SimulatedReader(self.sim).connect())
        self.card.select_application()

    def test_read_serial(self):
        self.assertEqual(self.card.read_serial().hex(), "08201223c46d4a18")

    def test_read_environment(self):
        env = self.card.read_environment()
        self.assertIsNotNone(env)
        self.assertEqual(env.data[0], 0x24)

    def test_read_contracts(self):
        contracts = self.card.read_contracts()
        self.assertEqual(len(contracts), 2)

    def test_read_event_log(self):
        events = self.card.read_event_log()
        self.assertEqual(len(events), 3)

    def test_read_counters(self):
        counters = self.card.read_counters()
        self.assertEqual(counters[0], 100)
        self.assertEqual(counters[1], 10)

    def test_read_ef_single_record(self):
        recs = self.card.read_ef(SFI_ENVIRONMENT, record=1)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].number, 1)

    def test_read_ef_all(self):
        recs = self.card.read_ef(SFI_EVENT_LOG)
        self.assertEqual(len(recs), 3)

    def test_read_ef_by_path(self):
        recs = self.card.read_ef_by_path(0x2020, record=1)
        self.assertEqual(len(recs), 1)

    def test_read_binary(self):
        blob = self.card.read_binary(0x01, 0, 32)
        self.assertEqual(len(blob), 32)


# ---------------------------------------------------------------------------
# Open session (no SAM, read-only)
# ---------------------------------------------------------------------------
class TestOpenSession(unittest.TestCase):
    def setUp(self):
        self.sim = SimulatedCalypsoCard()
        self.card = CalypsoCard(SimulatedReader(self.sim).connect())
        self.card.select_application()

    def test_open_and_close_session(self):
        sess = self.card.open_session(key_index=KEY_DEBIT)
        self.assertTrue(self.card.session_open)
        self.assertFalse(sess.secure)
        env = self.card.read_environment()
        self.assertIsNotNone(env)
        self.assertTrue(self.card.close_session())
        self.assertFalse(self.card.session_open)

    def test_write_without_sam_raises(self):
        self.card.open_session()
        with self.assertRaises(CalypsoNoSamError):
            self.card.update_record(SFI_CONTRACTS, 1, b"\x02" + b"\x00" * 28)
        self.card.abort_secure_session()

    def test_open_session_requires_selection(self):
        fresh = CalypsoCard(SimulatedReader(SimulatedCalypsoCard()).connect())
        with self.assertRaises(CalypsoSessionError):
            fresh.open_session()


# ---------------------------------------------------------------------------
# Secure session + writes (SAM-backed)
# ---------------------------------------------------------------------------
class TestSecureSessionWrites(unittest.TestCase):
    def setUp(self):
        self.key = b"\x07" * 16
        self.sim = SimulatedCalypsoCard(key=self.key)
        self.card = CalypsoCard(SimulatedReader(self.sim).connect())
        self.sam = SimulatedSam(key=self.key)
        self.card.select_application()

    def test_secure_session_roundtrip(self):
        sess = self.card.open_secure_session(self.sam, key_index=KEY_DEBIT)
        self.assertTrue(sess.secure)
        self.assertTrue(self.card.session_open)
        self.assertTrue(self.card.close_secure_session())

    def test_update_record(self):
        with CalypsoSession(self.card, self.sam):
            self.card.update_record(SFI_CONTRACTS, 1, b"\x05" + b"\x00" * 28)
        self.assertEqual(self.sim.files[SFI_CONTRACTS][0][0], 0x05)

    def test_write_record(self):
        with CalypsoSession(self.card, self.sam):
            self.card.write_record(SFI_CONTRACTS, 2, b"\x0f" + b"\x00" * 28)
        self.assertEqual(self.sim.files[SFI_CONTRACTS][1][0], 0x0f)

    def test_append_record(self):
        before = len(self.sim.files[SFI_EVENT_LOG])
        with CalypsoSession(self.card, self.sam):
            self.card.append_record(SFI_EVENT_LOG, b"\x11" * 29)
        self.assertEqual(len(self.sim.files[SFI_EVENT_LOG]), before + 1)

    def test_increase_counter(self):
        with CalypsoSession(self.card, self.sam, key_index=KEY_RELOAD):
            result = self.card.increase_counter(SFI_COUNTERS, 0, 5)
        self.assertEqual(int.from_bytes(result, "big"), 105)

    def test_decrease_counter(self):
        with CalypsoSession(self.card, self.sam):
            result = self.card.decrease_counter(SFI_COUNTERS, 0, 20)
        self.assertEqual(int.from_bytes(result, "big"), 80)

    def test_write_binary(self):
        with CalypsoSession(self.card, self.sam):
            self.card.write_binary(0x01, 0, b"\xaa\xbb\xcc\xdd")
        self.assertEqual(bytes(self.sim.binary[0x01][:4]), b"\xaa\xbb\xcc\xdd")

    def test_wrong_key_fails_authentication(self):
        bad_sam = SimulatedSam(key=b"\x00" * 16)
        self.card.open_secure_session(bad_sam)
        self.card.update_record(SFI_CONTRACTS, 1, b"\x01" + b"\x00" * 28)
        with self.assertRaises(CardError):
            self.card.close_secure_session()


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------
class TestErrorPaths(unittest.TestCase):
    def setUp(self):
        self.key = b"\x07" * 16
        self.sim = SimulatedCalypsoCard(key=self.key)
        self.card = CalypsoCard(SimulatedReader(self.sim).connect())
        self.sam = SimulatedSam(key=self.key)
        self.card.select_application()

    def test_write_without_session_raises(self):
        with self.assertRaises(CalypsoSessionError):
            self.card.update_record(SFI_CONTRACTS, 1, b"\x00" * 29)

    def test_secure_session_without_sam_raises(self):
        with self.assertRaises(CalypsoNoSamError):
            self.card.open_secure_session()

    def test_close_without_session_raises(self):
        with self.assertRaises(CalypsoSessionError):
            self.card.close_secure_session()

    def test_attach_sam_enables_secure_session(self):
        self.card.attach_sam(self.sam)
        self.assertTrue(self.card.has_sam)
        sess = self.card.open_secure_session()
        self.assertTrue(sess.secure)
        self.card.close_secure_session()


class TestBasicProfileWriteRestrictions(unittest.TestCase):
    def setUp(self):
        self.key = b"\x07" * 16
        self.sim = SimulatedCalypsoCard.basic(key=self.key)
        self.card = CalypsoCard(SimulatedReader(self.sim).connect())
        self.sam = SimulatedSam(key=self.key)
        self.card.select_application(self.sim.AID)
        self.assertEqual(self.card.profile, CalypsoProfile.BASIC)

    def test_write_record_unsupported_on_basic(self):
        self.card.open_secure_session(self.sam)
        with self.assertRaises(CalypsoWriteError):
            self.card.write_record(SFI_CONTRACTS, 1, b"\x00" * 29)
        self.card.abort_secure_session()

    def test_increase_unsupported_on_basic(self):
        self.card.open_secure_session(self.sam)
        with self.assertRaises(CalypsoWriteError):
            self.card.increase_counter(SFI_COUNTERS, 0, 1)
        self.card.abort_secure_session()

    def test_update_record_supported_on_basic(self):
        # UPDATE RECORD is not in the Basic-unsupported set, so it should succeed.
        with CalypsoSession(self.card, self.sam):
            self.card.update_record(SFI_CONTRACTS, 1, b"\x03" + b"\x00" * 28)
        self.assertEqual(self.sim.files[SFI_CONTRACTS][0][0], 0x03)


# ---------------------------------------------------------------------------
# CalypsoSession context manager
# ---------------------------------------------------------------------------
class TestCalypsoSessionContextManager(unittest.TestCase):
    def setUp(self):
        self.key = b"\x07" * 16
        self.sim = SimulatedCalypsoCard(key=self.key)
        self.card = CalypsoCard(SimulatedReader(self.sim).connect())
        self.sam = SimulatedSam(key=self.key)
        self.card.select_application()

    def test_read_only_session_without_sam(self):
        with CalypsoSession(self.card) as card:
            self.assertTrue(card.session_open)
            self.assertIsNotNone(card.read_environment())
        self.assertFalse(self.card.session_open)

    def test_secure_session_commits(self):
        with CalypsoSession(self.card, self.sam) as card:
            card.update_record(SFI_CONTRACTS, 1, b"\x09" + b"\x00" * 28)
        self.assertFalse(self.card.session_open)
        self.assertEqual(self.sim.files[SFI_CONTRACTS][0][0], 0x09)

    def test_session_aborts_on_exception(self):
        with self.assertRaises(ValueError):
            with CalypsoSession(self.card, self.sam):
                raise ValueError("boom")
        self.assertFalse(self.card.session_open)


if __name__ == "__main__":
    unittest.main()
