"""Calypso transport card support (contact interface) for the OMNIKEY 3021.

Two layers:

1. **Plain read** (no security module needed) - application selection, startup
   info / serial decoding, SELECT FILE, READ RECORD(S), READ BINARY, GET DATA.
   This is what a free-access read of an OPUS / Navigo / MOBIB / Oura card gives
   you, and what works on a dual-interface card through the 3021 today.

2. **Secure session** (needs a Calypso SAM) - OPEN/CLOSE SECURE SESSION with the
   card MAC verified by the SAM, and inside the session UPDATE/APPEND RECORD,
   INCREASE/DECREASE counters.  This is how you *write* a Calypso card.  Writing
   requires a Calypso SAM (a security-module card) personalised with the same
   keys as your cards; you provide it through the ``CalypsoSam`` interface
   (``PcscSam`` runs a real SAM in a second reader).

IMPORTANT - before production writes:
    The secure-session and SAM APDU byte layouts vary by Calypso revision
    (Prime Rev 2.4 uses CLA 94, Rev 3.x uses CLA 00) and by SAM product.  The
    constants at the top of this module follow the public Calypso specification
    and Eclipse Keyple; VERIFY them against your own card revision and SAM before
    you rely on writes.  The read path does not depend on any of this.

This module never bypasses card security: a write only succeeds if your SAM
holds the right keys.  There is no way to forge a Calypso MAC without them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable

from .apdu import CommandAPDU, ResponseAPDU, transmit_apdu
from .channel import CardChannel
from .errors import CardError, CredentialError, OmnikeyError, UnsupportedCardError

# -- class bytes (card revision) --------------------------------------------------
CLA_REV3 = 0x00     # Calypso Prime Rev 3.x, Calypso Light, most modern cards
CLA_REV2 = 0x94     # Calypso Rev 2.4 legacy (some OPUS / older cards)

# -- card instructions ------------------------------------------------------------
INS_SELECT = 0xA4
INS_READ_RECORDS = 0xB2
INS_UPDATE_RECORD = 0xDC
INS_WRITE_RECORD = 0xD2
INS_APPEND_RECORD = 0xE2
INS_READ_BINARY = 0xB0
INS_UPDATE_BINARY = 0xD6
INS_INCREASE = 0x32
INS_DECREASE = 0x30
INS_GET_DATA = 0xCA
INS_GET_CHALLENGE = 0x84
INS_OPEN_SECURE_SESSION = 0x8A
INS_CLOSE_SECURE_SESSION = 0x8E
INS_VERIFY_PIN = 0x20
INS_CHANGE_PIN = 0xD8
INS_SV_GET = 0x7C
INS_SV_RELOAD = 0xB8
INS_SV_DEBIT = 0xBA
INS_INVALIDATE = 0x04
INS_REHABILITATE = 0x44
INS_RATIFICATION = 0xB2  # a read of a non-existent record ratifies a prior session

# READ RECORDS P2 low nibble
P2_READ_ONE_RECORD = 0x04    # read the single record P1
P2_READ_FROM_P1 = 0x05       # read records P1..last

# Well-known application identifiers (DF names)
AID_1TIC_ICA = bytes.fromhex("315449432E494341")   # "1TIC.ICA" - OPUS, Navigo, most Intercode/Calypso (Prime)
AID_NAVIGO = bytes.fromhex("A0000004040125090101")
AID_CD_LIGHT_GTML = bytes.fromhex("315449432E49434131")
AID_CALYPSO_PRIME = AID_1TIC_ICA                      # Calypso Prime transport application
AID_CALYPSO_LIGHT = bytes.fromhex("304554502E494341")  # "0ETP.ICA" - Calypso Light
AID_CALYPSO_BASIC = bytes.fromhex("315449432E494342")  # "1TIC.ICB" - Calypso Basic / CD97
# AIDs tried, in order, when auto-detecting the Calypso application on a card.
DEFAULT_AID_CANDIDATES = (AID_1TIC_ICA, AID_NAVIGO, AID_CALYPSO_LIGHT, AID_CALYPSO_BASIC)
KNOWN_AIDS = {
    "315449432E494341": "1TIC.ICA (Calypso Prime transport application)",
    "A0000004040125090101": "Navigo",
    "315449432E49434131": "CD Light / GTML",
    "304554502E494341": "0ETP.ICA (Calypso Light)",
    "315449432E494342": "1TIC.ICB (Calypso Basic / CD97)",
}

# Standard transport file layout (SFI).  Layouts differ between networks
# (Intercode in France, custom elsewhere); these are the common Calypso SFIs.
SFI_ENVIRONMENT = 0x07       # EF Environment & Holder (issuer, card expiry, holder)
SFI_EVENT_LOG = 0x08         # EF Event log (last validations)
SFI_CONTRACTS = 0x09         # EF Contracts (season passes / tickets)
SFI_COUNTERS = 0x19          # EF Counters (trip counters, stored rides)
SFI_SPECIAL_EVENTS = 0x1D    # EF Special events
SFI_CONTRACT_LIST = 0x1E     # EF Contract list / pointers
STANDARD_SFIS = {
    SFI_ENVIRONMENT: "Environment & Holder", SFI_EVENT_LOG: "Event log", SFI_CONTRACTS: "Contracts",
    SFI_COUNTERS: "Counters", SFI_SPECIAL_EVENTS: "Special events", SFI_CONTRACT_LIST: "Contract list",
}

# Startup-info platform bytes (byte 1 of the 7-byte startup information)
PLATFORMS = {0x01: "Calypso Light", 0x02: "Calypso Basic", 0x03: "Calypso Prime",
             0x04: "Calypso Prime Rev3.1", 0x06: "Calypso Prime Rev3.2"}
APP_TYPES = {0x01: "Calypso Rev1", 0x04: "Calypso Rev2", 0x06: "Calypso Rev3",
             0x1F: "Calypso Prime", 0x20: "Calypso Light"}

# Calypso key indexes used inside a secure session (KIF/KVC selection is on the SAM).
KEY_DEBIT = 1            # debit / read key (most common; used to open a read session)
KEY_RELOAD = 2           # reload / load key (top-ups, counter increases)
KEY_PERSONALIZATION = 3  # personalization / issuer key (structural writes)
KEY_NAMES = {KEY_DEBIT: "debit", KEY_RELOAD: "reload", KEY_PERSONALIZATION: "personalization"}


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------
class CalypsoProfile(Enum):
    """The Calypso product profile of a card, detected from its startup info / AID."""

    PRIME = "Calypso Prime"
    LIGHT = "Calypso Light"
    BASIC = "Calypso Basic"
    UNKNOWN = "Unknown Calypso profile"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


def detect_profile(aid: bytes | None = None, startup: "StartupInfo | None" = None) -> CalypsoProfile:
    """Best-effort detection of the Calypso profile from startup info first, then the AID.

    Startup-info platform byte is the most reliable signal; the application-type byte and
    the selected AID are used as fallbacks.
    """
    if startup is not None and startup.raw and len(startup.raw) >= 7:
        platform = startup.platform
        if platform == 0x01:
            return CalypsoProfile.LIGHT
        if platform == 0x02:
            return CalypsoProfile.BASIC
        if platform in (0x03, 0x04, 0x06):
            return CalypsoProfile.PRIME
        app_type = startup.application_type
        if app_type == 0x20:
            return CalypsoProfile.LIGHT
        if app_type in (0x1F, 0x06):
            return CalypsoProfile.PRIME
        if app_type == 0x04:
            return CalypsoProfile.BASIC
    if aid is not None:
        if aid == AID_CALYPSO_LIGHT:
            return CalypsoProfile.LIGHT
        if aid == AID_CALYPSO_BASIC:
            return CalypsoProfile.BASIC
        if aid in (AID_CALYPSO_PRIME, AID_NAVIGO, AID_CD_LIGHT_GTML):
            return CalypsoProfile.PRIME
    return CalypsoProfile.UNKNOWN


# Write instructions that a Calypso Basic card does not implement (reduced command set).
_BASIC_UNSUPPORTED = frozenset({INS_WRITE_RECORD, INS_INCREASE, INS_DECREASE})


# ---------------------------------------------------------------------------
# Calypso-specific errors
# ---------------------------------------------------------------------------
class CalypsoError(OmnikeyError):
    """Base class for Calypso-specific errors."""


class CalypsoSessionError(CalypsoError, CredentialError):
    """A session-related problem: a write outside a session, or a bad open/close sequence.

    Subclasses ``CredentialError`` for backward compatibility with earlier releases that
    raised ``CredentialError`` when a write ran outside an open session.
    """


class CalypsoNoSamError(CalypsoError):
    """A secure operation (write, secure session) was attempted without a SAM attached."""


class CalypsoWriteError(CalypsoError):
    """A write command is not permitted (unsupported by the profile, or file not writable)."""


# ---------------------------------------------------------------------------
# Elementary File metadata
# ---------------------------------------------------------------------------
class EFType(Enum):
    LINEAR = "linear"        # fixed-size records addressed by number (UPDATE RECORD)
    CYCLIC = "cyclic"        # ring buffer, newest first (APPEND RECORD)
    COUNTERS = "counters"    # 3-byte counters (INCREASE / DECREASE)
    BINARY = "binary"        # transparent binary file (READ/UPDATE BINARY)


@dataclass
class CalypsoEF:
    """Metadata describing a Calypso Elementary File (EF)."""

    sfi: int
    name: str = ""
    ef_type: EFType = EFType.LINEAR
    record_size: int = 29
    num_records: int = 1
    lid: int | None = None       # 2-byte Long Identifier (file path), if known

    def describe(self) -> str:
        return (f"EF {self.name or hex(self.sfi)} (SFI {self.sfi:#04x}, {self.ef_type.value}, "
                f"{self.num_records}x{self.record_size}B)")


# Standard transport EF map with metadata (common Calypso / Intercode layout).
STANDARD_EFS: dict[int, CalypsoEF] = {
    SFI_ENVIRONMENT: CalypsoEF(SFI_ENVIRONMENT, "Environment & Holder", EFType.LINEAR, 29, 1, 0x2001),
    SFI_EVENT_LOG: CalypsoEF(SFI_EVENT_LOG, "Event log", EFType.CYCLIC, 29, 3, 0x2010),
    SFI_CONTRACTS: CalypsoEF(SFI_CONTRACTS, "Contracts", EFType.LINEAR, 29, 4, 0x2020),
    SFI_COUNTERS: CalypsoEF(SFI_COUNTERS, "Counters", EFType.COUNTERS, 29, 1, 0x2069),
    SFI_SPECIAL_EVENTS: CalypsoEF(SFI_SPECIAL_EVENTS, "Special events", EFType.CYCLIC, 29, 1, 0x2040),
    SFI_CONTRACT_LIST: CalypsoEF(SFI_CONTRACT_LIST, "Contract list", EFType.LINEAR, 29, 1, 0x2050),
}


# ---------------------------------------------------------------------------
# Startup information / traceability
# ---------------------------------------------------------------------------
@dataclass
class StartupInfo:
    raw: bytes
    buffer_size: int = 0
    platform: int = 0
    application_type: int = 0
    application_subtype: int = 0
    software_issuer: int = 0
    software_version: int = 0
    software_revision: int = 0

    @classmethod
    def parse(cls, raw: bytes) -> "StartupInfo":
        b = bytes(raw)
        if len(b) < 7:
            return cls(b)
        return cls(b, b[0], b[1], b[2], b[3], b[4], b[5], b[6])

    def describe(self) -> dict[str, str]:
        return {
            "buffer size": str(self.buffer_size),
            "platform": PLATFORMS.get(self.platform, f"0x{self.platform:02X}"),
            "application type": APP_TYPES.get(self.application_type, f"0x{self.application_type:02X}"),
            "application subtype": f"0x{self.application_subtype:02X}",
            "software issuer": f"0x{self.software_issuer:02X}",
            "software version": f"{self.software_version}.{self.software_revision}",
        }


@dataclass
class CalypsoIdentity:
    aid: bytes
    serial: bytes                    # application serial number (8 bytes) - the card id
    startup: StartupInfo | None = None
    fci: bytes = b""
    revision: int = 3

    @property
    def serial_hex(self) -> str:
        return self.serial.hex().upper()

    def describe(self) -> list[str]:
        out = [f"AID: {self.aid.hex().upper()} ({KNOWN_AIDS.get(self.aid.hex().upper(), 'unknown')})",
               f"Application serial number: {self.serial_hex}",
               f"Calypso revision: {self.revision}"]
        if self.startup:
            for k, v in self.startup.describe().items():
                out.append(f"  {k}: {v}")
        return out


def _parse_fci(fci: bytes) -> tuple[bytes, StartupInfo | None]:
    """Extract the application serial (tag C7) and startup info (tag 53/07) from a Calypso FCI."""
    from .tlv import decode

    serial, startup = b"", None
    try:
        nodes = decode(fci)
    except ValueError:
        return serial, startup

    def walk(node):
        nonlocal serial, startup
        if node.tag == 0xC7 and len(node.value) == 8:
            serial = node.value
        elif node.tag in (0x53, 0x07) and len(node.value) >= 7 and startup is None:
            startup = StartupInfo.parse(node.value)
        for c in node.children:
            walk(c)

    for n in nodes:
        walk(n)
    return serial, startup


def _compact_tlv(data: bytes, want_tag: int) -> bytes:
    """Return the value of a compact-TLV object (high nibble = tag, low nibble = length)."""
    pos = 0
    data = bytes(data)
    while pos < len(data):
        tag, length = data[pos] >> 4, data[pos] & 0x0F
        pos += 1
        if pos + length > len(data):
            break
        if tag == want_tag:
            return data[pos:pos + length]
        pos += length
    return b""


# ---------------------------------------------------------------------------
# SAM (Secure Access Module) interface
# ---------------------------------------------------------------------------
@runtime_checkable
class CalypsoSam(Protocol):
    """A Calypso SAM computes and verifies session MACs; it holds the keys, not this code.

    The digest flow (Calypso Rev3): select_diversifier(card serial) -> get_challenge()
    gives the terminal challenge sent in OPEN SECURE SESSION -> digest_init() with the
    card's opening response -> digest_update() for every command and response exchanged
    in the session -> digest_close() returns the terminal MAC for CLOSE SECURE SESSION
    -> digest_authenticate() checks the card's returned MAC.
    """

    def select_diversifier(self, serial: bytes) -> None: ...
    def get_challenge(self) -> bytes: ...
    def digest_init(self, key_index: int, open_response: bytes) -> None: ...
    def digest_update(self, apdu: bytes) -> None: ...
    def digest_close(self) -> bytes: ...
    def digest_authenticate(self, card_mac: bytes) -> bool: ...


class CalypsoSamMixin:
    """High-level session helpers built on the low-level ``CalypsoSam`` digest primitives.

    Any object implementing the :class:`CalypsoSam` protocol can mix this in to gain the
    three convenience methods described in the Calypso terminal API:

    * ``open_secure_session(card, key_index, challenge)`` - diversify on the card serial,
      seed the digest from the card's opening response and return the terminal challenge
      that was sent to the card.
    * ``close_secure_session(card, digest)`` - fold the final exchange (if any) into the
      running digest and return the terminal (closing) MAC.
    * ``verify_mac(mac)`` - validate the card's returned MAC.
    """

    def open_secure_session(self, card: "CalypsoCard", key_index: int = KEY_DEBIT,
                            challenge: bytes | None = None) -> bytes:
        serial = card.identity.serial if card.identity else b""
        self.select_diversifier(serial)               # type: ignore[attr-defined]
        return challenge if challenge is not None else self.get_challenge()  # type: ignore[attr-defined]

    def seed_from_open_response(self, key_index: int, open_response: bytes) -> None:
        self.digest_init(key_index, open_response)    # type: ignore[attr-defined]

    def close_secure_session(self, card: "CalypsoCard | None" = None, digest: bytes = b"") -> bytes:
        if digest:
            self.digest_update(digest)                # type: ignore[attr-defined]
        return self.digest_close()                    # type: ignore[attr-defined]

    def verify_mac(self, mac: bytes) -> bool:
        return self.digest_authenticate(mac)          # type: ignore[attr-defined]


# SAM APDUs (CLA 80).  VERIFY against your SAM product before production use.
SAM_CLA = 0x80
SAM_INS_SELECT_DIVERSIFIER = 0x14
SAM_INS_GET_CHALLENGE = 0x84
SAM_INS_DIGEST_INIT = 0x8A
SAM_INS_DIGEST_UPDATE = 0x8C
SAM_INS_DIGEST_CLOSE = 0x8E
SAM_INS_DIGEST_AUTHENTICATE = 0x82


class PcscSam(CalypsoSamMixin):
    """A real Calypso SAM in a second reader, driven over its own CardChannel.

    NOTE: the exact SAM APDU parameters depend on the SAM product (e.g. C1, HSM).
    The bytes here follow the public Calypso SAM command set; confirm them with
    your SAM vendor.  Until then, use ``SimulatedSam`` for the flow and your own
    integration tests.
    """

    def __init__(self, channel: CardChannel):
        self.channel = channel

    def _send(self, ins: int, p1: int, p2: int, data: bytes = b"", le: int | None = None) -> bytes:
        resp = transmit_apdu(self.channel.transmit, CommandAPDU(SAM_CLA, ins, p1, p2, data, le))
        return resp.check(allow_warnings=True).data

    def select_diversifier(self, serial: bytes) -> None:
        self._send(SAM_INS_SELECT_DIVERSIFIER, 0x00, 0x00, bytes(serial))

    def get_challenge(self) -> bytes:
        return self._send(SAM_INS_GET_CHALLENGE, 0x00, 0x00, le=0x08)

    def digest_init(self, key_index: int, open_response: bytes) -> None:
        self._send(SAM_INS_DIGEST_INIT, 0x00, key_index, bytes(open_response))

    def digest_update(self, apdu: bytes) -> None:
        self._send(SAM_INS_DIGEST_UPDATE, 0x00, 0x00, bytes(apdu))

    def digest_close(self) -> bytes:
        return self._send(SAM_INS_DIGEST_CLOSE, 0x00, 0x00, le=0x04)

    def digest_authenticate(self, card_mac: bytes) -> bool:
        try:
            self._send(SAM_INS_DIGEST_AUTHENTICATE, 0x00, 0x00, bytes(card_mac))
            return True
        except CardError:
            return False


# ---------------------------------------------------------------------------
# Card
# ---------------------------------------------------------------------------
@dataclass
class CalypsoRecord:
    sfi: int
    number: int
    data: bytes


@dataclass
class SecureSession:
    sam: CalypsosSam | None  # type: ignore  # noqa: F821
    key_index: int
    card_challenge: bytes
    open: bool = True
    secure: bool = True          # True = SAM-backed (writes allowed); False = open session (read-only)
    exchanges: list[bytes] = field(default_factory=list)


class CalypsoCard:
    """A Calypso transport card on a contact CardChannel."""

    def __init__(self, channel: CardChannel, revision: int | None = None,
                 sam: CalypsoSam | None = None):
        self.channel = channel
        self.cla = CLA_REV3 if revision in (None, 3) else CLA_REV2
        self.revision = revision or 3
        self.identity: CalypsoIdentity | None = None
        self.profile: CalypsoProfile = CalypsoProfile.UNKNOWN
        self.efs: dict[int, CalypsoEF] = dict(STANDARD_EFS)
        self.sam: CalypsoSam | None = sam
        self._session: SecureSession | None = None

    # -- SAM management ------------------------------------------------------------
    def attach_sam(self, sam: CalypsoSam | None) -> None:
        """Attach (or detach with ``None``) a SAM used for secure sessions and writes."""
        self.sam = sam

    @property
    def has_sam(self) -> bool:
        return self.sam is not None

    # -- low level -----------------------------------------------------------------
    def _apdu(self, ins: int, p1: int, p2: int, data: bytes = b"", le: int | None = None,
              check: bool = True, allow_warnings: bool = True, cla: int | None = None) -> ResponseAPDU:
        cmd = CommandAPDU(self.cla if cla is None else cla, ins, p1, p2, bytes(data), le)
        resp = transmit_apdu(self.channel.transmit, cmd)
        sess = self._session
        if (sess and sess.open and sess.secure and sess.sam is not None
                and ins not in (INS_OPEN_SECURE_SESSION,)):
            # feed both the command and the response to the SAM digest
            sess.sam.digest_update(cmd.to_bytes())
            sess.sam.digest_update(resp.to_bytes())
        if check:
            resp.check(cmd.to_bytes(), allow_warnings=allow_warnings)
        return resp

    # -- selection -----------------------------------------------------------------
    def select_application(self, aid: bytes = AID_1TIC_ICA, try_legacy: bool = True,
                           required: bool = True) -> CalypsoIdentity | None:
        """SELECT the Calypso application by AID; falls back to CLA 94 for Rev2 cards.

        Some older cards (many Rev2 OPUS cards) use *implicit selection*: the
        application is already active after reset and SELECT-by-AID is unsupported.
        With ``required=False`` a failure returns ``None`` and you read files
        directly by SFI (see :meth:`implicit_identity`).
        """
        last: OmnikeyError | None = None
        for cla in (self.cla, CLA_REV2 if try_legacy else self.cla):
            try:
                cmd = CommandAPDU(cla, INS_SELECT, 0x04, 0x00, bytes(aid), 0)
                resp = transmit_apdu(self.channel.transmit, cmd).check(cmd.to_bytes(), allow_warnings=True)
                self.cla = cla
                self.revision = 2 if cla == CLA_REV2 else 3
                serial, startup = _parse_fci(resp.data)
                self.identity = CalypsoIdentity(bytes(aid), serial, startup, resp.data, self.revision)
                self.profile = detect_profile(bytes(aid), startup)
                return self.identity
            except (CardError, OmnikeyError) as exc:
                last = exc
        if required:
            raise UnsupportedCardError(
                f"no Calypso application {aid.hex().upper()} selectable on this card ({last}). "
                "If it is a transport card it may use implicit selection - retry with required=False "
                "or the CLI --implicit flag to read files directly by SFI."
            )
        return None

    def implicit_identity(self) -> CalypsoIdentity:
        """Identity for an implicit-selection card (SELECT-by-AID unsupported).

        The card serial is taken from the ATR historical bytes, which for these
        cards are compact-TLV: tag 5 (nibble) carries the card serial number.
        """
        from .atr import parse_atr

        hist = parse_atr(self.channel.atr).historical
        serial = _compact_tlv(hist, 0x5) or hist
        ident = CalypsoIdentity(b"", serial, None, b"", self.revision)
        self.identity = ident
        return ident

    def auto_select(self, candidates: tuple[bytes, ...] = DEFAULT_AID_CANDIDATES) -> CalypsoIdentity:
        """Try each known Calypso AID in turn and select the first one present on the card.

        Profile detection happens automatically on the successful SELECT.
        """
        last: OmnikeyError | None = None
        for aid in candidates:
            try:
                return self.select_application(aid)
            except (UnsupportedCardError, CardError, OmnikeyError) as exc:
                last = exc
        raise UnsupportedCardError(f"no known Calypso application found on this card ({last})")

    def select_file(self, lid: int) -> bytes:
        """SELECT a file by its 2-byte Long Identifier; returns the FCI."""
        return self._apdu(INS_SELECT, 0x08 if self.revision >= 3 else 0x00, 0x00, lid.to_bytes(2, "big"), 0).data

    # -- plain reads (no SAM) --------------------------------------------------------
    def read_record(self, sfi: int, number: int = 1) -> bytes:
        return self._apdu(INS_READ_RECORDS, number, (sfi << 3) | P2_READ_ONE_RECORD, le=0).data

    def read_records(self, sfi: int, first: int = 1, last: int | None = None, record_size: int = 29) -> list[CalypsoRecord]:
        """Read records from an EF by SFI.  Reads one at a time (portable across layouts)."""
        out: list[CalypsoRecord] = []
        n = first
        while last is None or n <= last:
            resp = self._apdu(INS_READ_RECORDS, n, (sfi << 3) | P2_READ_ONE_RECORD, le=0, check=False)
            if resp.sw in (0x6A83, 0x6A82, 0x6B00, 0x6981):
                break
            if resp.sw1 == 0x6C:
                resp = self._apdu(INS_READ_RECORDS, n, (sfi << 3) | P2_READ_ONE_RECORD, le=resp.sw2, check=False)
            if not resp.ok and not resp.warning:
                if out:
                    break
                resp.check()
            out.append(CalypsoRecord(sfi, n, resp.data))
            n += 1
            if last is None and len(out) > 250:
                break
        return out

    def read_binary(self, sfi: int, offset: int = 0, length: int = 0) -> bytes:
        p1 = 0x80 | (sfi & 0x1F) if sfi else (offset >> 8) & 0x7F
        return self._apdu(INS_READ_BINARY, p1, offset & 0xFF, le=length or 0, cla=CLA_REV3).data

    def get_data(self, tag: int) -> bytes:
        return self._apdu(INS_GET_DATA, (tag >> 8) & 0xFF, tag & 0xFF, le=0).data

    def get_challenge(self) -> bytes:
        return self._apdu(INS_GET_CHALLENGE, 0x00, 0x00, le=0x08).data

    def dump(self, sfis: dict[int, str] | None = None) -> dict[int, list[CalypsoRecord]]:
        """Read every record of the standard transport files (or a custom SFI map)."""
        out: dict[int, list[CalypsoRecord]] = {}
        for sfi in (sfis or STANDARD_SFIS):
            try:
                recs = self.read_records(sfi)
            except (CardError, OmnikeyError):
                recs = []
            if recs:
                out[sfi] = recs
        return out

    # -- high-level read helpers (open access, no SAM) --------------------------------
    def read_serial(self) -> bytes:
        """Return the card serial number (CSN / application serial), selecting if needed."""
        ident = self.identity or self.select_application()
        return ident.serial

    def read_environment(self) -> CalypsoRecord | None:
        """Read record 1 of EF Environment & Holder."""
        recs = self.read_records(SFI_ENVIRONMENT, 1, 1)
        return recs[0] if recs else None

    def read_contracts(self, max_slots: int = 4) -> list[CalypsoRecord]:
        """Read all contract slots (EF Contracts)."""
        return self.read_records(SFI_CONTRACTS, 1, max_slots)

    def read_event_log(self, max_events: int = 3) -> list[CalypsoRecord]:
        """Read the event log records (EF Event log), newest first on a cyclic file."""
        return self.read_records(SFI_EVENT_LOG, 1, max_events)

    def read_counters(self) -> list[int]:
        """Read EF Counters and decode the 3-byte counter values it packs into record 1."""
        recs = self.read_records(SFI_COUNTERS, 1, 1)
        if not recs:
            return []
        data = recs[0].data
        return [int.from_bytes(data[i:i + 3], "big") for i in range(0, len(data) - 2, 3)]

    def read_ef(self, sfi: int, record: int | None = None) -> list[CalypsoRecord]:
        """Read an arbitrary EF by SFI: a single record if ``record`` is given, else all records."""
        if record is not None:
            return [CalypsoRecord(sfi, record, self.read_record(sfi, record))]
        return self.read_records(sfi)

    def read_ef_by_path(self, lid: int, record: int | None = None) -> list[CalypsoRecord]:
        """SELECT an EF by its 2-byte Long Identifier (path) then READ RECORD(S) by current file."""
        self.select_file(lid)
        # After SELECT FILE the current EF is addressed with SFI 0 in READ RECORDS.
        return self.read_ef(0x00, record)

    # -- open session (no SAM, read-only) ---------------------------------------------
    def open_session(self, key_index: int = KEY_DEBIT, read_sfi: int = 0,
                     read_record: int = 0) -> SecureSession:
        """OPEN a Calypso session WITHOUT a SAM (ratification / open-session mode).

        This sends OPEN SECURE SESSION with the debit key index and a random terminal
        challenge, giving read access to the files in the session.  It is *read-only*:
        no MAC can be produced without a SAM, so any write raises :class:`CalypsoNoSamError`.
        """
        if self.identity is None:
            raise CalypsoSessionError("select the application before opening a session")
        terminal_challenge = os.urandom(8)
        p1 = read_record & 0xFF
        p2 = ((read_sfi & 0x1F) << 3) | (key_index & 0x07)
        resp = self._apdu(INS_OPEN_SECURE_SESSION, p1, p2, terminal_challenge, le=0,
                          check=True, allow_warnings=True)
        card_challenge = resp.data[:4] if resp.data else b""
        self._session = SecureSession(None, key_index, card_challenge, secure=False)
        return self._session

    # -- secure session (needs a SAM) --------------------------------------------------
    def open_secure_session(self, sam: CalypsoSam | None = None, key_index: int = KEY_DEBIT,
                            read_sfi: int = 0, read_record: int = 0) -> SecureSession:
        """OPEN SECURE SESSION with a SAM.  ``key_index`` selects the key (1 debit, 2 reload, 3 perso).

        Uses the SAM passed here, or the SAM attached with :meth:`attach_sam` / the constructor.
        The SAM diversifies on the card serial, produces the terminal challenge sent to the
        card, and the card's opening response seeds the SAM digest.  Every command until
        ``close_secure_session`` is included in the MAC.

        Raises :class:`CalypsoNoSamError` if no SAM is available - use :meth:`open_session`
        for a read-only session in that case.
        """
        sam = sam or self.sam
        if sam is None:
            raise CalypsoNoSamError(
                "a secure session requires a SAM; attach one with attach_sam() or use "
                "open_session() for read-only access")
        if self.identity is None:
            raise CalypsoSessionError("select the application before opening a secure session")
        sam.select_diversifier(self.identity.serial)
        terminal_challenge = sam.get_challenge()
        # Rev3.1 layout: P1 = record to read, P2 = (SFI<<3) | key index; data = terminal challenge.
        # (Verify P1/P2 for your card revision - see module docstring.)
        p1 = read_record & 0xFF
        p2 = ((read_sfi & 0x1F) << 3) | (key_index & 0x07)
        resp = self._apdu(INS_OPEN_SECURE_SESSION, p1, p2, terminal_challenge, le=0,
                          check=True, allow_warnings=True)
        # Opening response: card challenge (first bytes) + optional record data.
        card_challenge = resp.data[:4] if resp.data else b""
        sam.digest_init(key_index, resp.data)
        self._session = SecureSession(sam, key_index, card_challenge, secure=True)
        return self._session

    def close_secure_session(self, ratify: bool = True) -> bool:
        """CLOSE the session.

        * Secure session: the SAM's terminal MAC is sent and the card's MAC verified.
        * Open session (no SAM): CLOSE is sent with no terminal MAC (nothing to verify).
        """
        if self._session is None or not self._session.open:
            raise CalypsoSessionError("no session is open")
        sess = self._session
        if not sess.secure or sess.sam is None:
            # Open session: close with an empty terminal MAC, nothing to authenticate.
            cmd = CommandAPDU(self.cla, INS_CLOSE_SECURE_SESSION, 0x80 if ratify else 0x00, 0x00, b"", 0)
            transmit_apdu(self.channel.transmit, cmd).check(cmd.to_bytes(), allow_warnings=True)
            self._session = None
            return True
        terminal_mac = sess.sam.digest_close()
        cmd = CommandAPDU(self.cla, INS_CLOSE_SECURE_SESSION, 0x80 if ratify else 0x00, 0x00, terminal_mac, 0)
        resp = transmit_apdu(self.channel.transmit, cmd).check(cmd.to_bytes(), allow_warnings=True)
        self._session = None
        card_mac = resp.data[:4]
        if not sess.sam.digest_authenticate(card_mac):
            raise CredentialError("card MAC not authenticated by the SAM - session is not trusted")
        return True

    def close_session(self, ratify: bool = True) -> bool:
        """Alias for :meth:`close_secure_session` (works for open sessions too)."""
        return self.close_secure_session(ratify=ratify)

    def abort_secure_session(self) -> None:
        self._session = None

    @property
    def session_open(self) -> bool:
        return self._session is not None and self._session.open

    def _require_session(self, ins: int | None = None) -> None:
        """Ensure a write can run: a session must be open, SAM-backed, and support the command."""
        if self._session is None or not self._session.open:
            raise CalypsoSessionError(
                "this write must run inside a session (open_secure_session or open_session first)")
        if not self._session.secure or self._session.sam is None:
            raise CalypsoNoSamError(
                "writes require a SAM-backed secure session; the current session is read-only "
                "(open_secure_session with a SAM to write)")
        if ins is not None and self.profile is CalypsoProfile.BASIC and ins in _BASIC_UNSUPPORTED:
            raise CalypsoWriteError(
                f"command {ins:#04x} is not supported by a Calypso Basic card")

    # -- writes (inside a secure session) -------------------------------------------------
    @staticmethod
    def _sfi_p2(sfi: int) -> int:
        """P2 byte addressing an EF by SFI for record commands: (SFI<<3) | 4."""
        return ((sfi & 0x1F) << 3) | P2_READ_ONE_RECORD

    def update_record(self, sfi: int, number: int, data: bytes) -> None:
        self._require_session(INS_UPDATE_RECORD)
        self._apdu(INS_UPDATE_RECORD, number, self._sfi_p2(sfi), bytes(data))

    def write_record(self, sfi: int, number: int, data: bytes) -> None:
        self._require_session(INS_WRITE_RECORD)
        self._apdu(INS_WRITE_RECORD, number, self._sfi_p2(sfi), bytes(data))

    def append_record(self, sfi: int, data: bytes) -> None:
        self._require_session(INS_APPEND_RECORD)
        self._apdu(INS_APPEND_RECORD, 0x00, self._sfi_p2(sfi), bytes(data))

    def increase_counter(self, sfi: int, counter: int, amount: int) -> bytes:
        self._require_session(INS_INCREASE)
        return self._apdu(INS_INCREASE, counter, self._sfi_p2(sfi), amount.to_bytes(3, "big"), le=0).data

    def decrease_counter(self, sfi: int, counter: int, amount: int) -> bytes:
        self._require_session(INS_DECREASE)
        return self._apdu(INS_DECREASE, counter, self._sfi_p2(sfi), amount.to_bytes(3, "big"), le=0).data

    def write_binary(self, sfi: int, offset: int, data: bytes) -> None:
        """UPDATE BINARY into a transparent EF (ISO CLA 0x00), inside a secure session."""
        self._require_session(INS_UPDATE_BINARY)
        p1 = 0x80 | (sfi & 0x1F) if sfi else (offset >> 8) & 0x7F
        self._apdu(INS_UPDATE_BINARY, p1, offset & 0xFF, bytes(data), cla=CLA_REV3)

    # -- PIN ------------------------------------------------------------------------------
    def verify_pin(self, pin: bytes) -> None:
        self._apdu(INS_VERIFY_PIN, 0x00, 0x00, bytes(pin))

    # -- high level ------------------------------------------------------------------------
    def info(self) -> dict[str, str]:
        ident = self.identity or self.select_application()
        out = {"aid": ident.aid.hex().upper(), "serial": ident.serial_hex,
               "revision": str(ident.revision), "profile": str(self.profile)}
        if ident.startup:
            out.update(ident.startup.describe())
        for sfi, recs in self.dump().items():
            out[f"EF {STANDARD_SFIS.get(sfi, hex(sfi))}"] = f"{len(recs)} record(s), {len(recs[0].data) if recs else 0} bytes each"
        return out


# ---------------------------------------------------------------------------
# Session context manager
# ---------------------------------------------------------------------------
class CalypsoSession:
    """Context manager that opens a Calypso session and always closes/aborts it cleanly.

    With a SAM (passed here or already attached to the card) it opens a *secure* session
    so writes are allowed; without one it opens a read-only *open* session::

        with CalypsoSession(card, sam, key_index=KEY_DEBIT):
            card.update_record(SFI_CONTRACTS, 1, data)   # committed + MAC-verified on exit

        with CalypsoSession(card):                        # no SAM -> read-only
            card.read_contracts()

    On a normal exit the session is closed (MAC verified for secure sessions); if the body
    raises, the session is aborted so the card is left in a clean state.
    """

    def __init__(self, card: CalypsoCard, sam: CalypsoSam | None = None,
                 key_index: int = KEY_DEBIT, ratify: bool = True):
        self.card = card
        self.sam = sam
        self.key_index = key_index
        self.ratify = ratify
        self.secure = False

    def __enter__(self) -> CalypsoCard:
        sam = self.sam or self.card.sam
        if sam is not None:
            self.card.open_secure_session(sam, key_index=self.key_index)
            self.secure = True
        else:
            self.card.open_session(key_index=self.key_index)
            self.secure = False
        return self.card

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None:
            self.card.abort_secure_session()
            return False
        self.card.close_secure_session(ratify=self.ratify)
        return False


# alias fix for the forward reference above
CalypsosSam = CalypsoSam
SecureSession.__annotations__["sam"] = CalypsoSam
