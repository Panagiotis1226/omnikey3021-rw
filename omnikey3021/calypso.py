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

from dataclasses import dataclass, field
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
AID_1TIC_ICA = bytes.fromhex("315449432E494341")   # "1TIC.ICA" - OPUS, Navigo, most Intercode/Calypso
AID_NAVIGO = bytes.fromhex("A0000004040125090101")
AID_CD_LIGHT_GTML = bytes.fromhex("315449432E49434131")
KNOWN_AIDS = {
    "315449432E494341": "1TIC.ICA (Calypso transport application)",
    "A0000004040125090101": "Navigo",
    "315449432E49434131": "CD Light / GTML",
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


# SAM APDUs (CLA 80).  VERIFY against your SAM product before production use.
SAM_CLA = 0x80
SAM_INS_SELECT_DIVERSIFIER = 0x14
SAM_INS_GET_CHALLENGE = 0x84
SAM_INS_DIGEST_INIT = 0x8A
SAM_INS_DIGEST_UPDATE = 0x8C
SAM_INS_DIGEST_CLOSE = 0x8E
SAM_INS_DIGEST_AUTHENTICATE = 0x82


class PcscSam:
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
    sam: CalypsosSam  # type: ignore  # noqa: F821
    key_index: int
    card_challenge: bytes
    open: bool = True
    exchanges: list[bytes] = field(default_factory=list)


class CalypsoCard:
    """A Calypso transport card on a contact CardChannel."""

    def __init__(self, channel: CardChannel, revision: int | None = None):
        self.channel = channel
        self.cla = CLA_REV3 if revision in (None, 3) else CLA_REV2
        self.revision = revision or 3
        self.identity: CalypsoIdentity | None = None
        self._session: SecureSession | None = None

    # -- low level -----------------------------------------------------------------
    def _apdu(self, ins: int, p1: int, p2: int, data: bytes = b"", le: int | None = None,
              check: bool = True, allow_warnings: bool = True) -> ResponseAPDU:
        cmd = CommandAPDU(self.cla, ins, p1, p2, bytes(data), le)
        resp = transmit_apdu(self.channel.transmit, cmd)
        if self._session and self._session.open and ins not in (INS_OPEN_SECURE_SESSION,):
            # feed both the command and the response to the SAM digest
            self._session.sam.digest_update(cmd.to_bytes())
            self._session.sam.digest_update(resp.to_bytes())
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
        return self._apdu(INS_READ_BINARY, p1, offset & 0xFF, le=length or 0).data

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

    # -- secure session (needs a SAM) --------------------------------------------------
    def open_secure_session(self, sam: CalypsoSam, key_index: int = 1, read_sfi: int = 0,
                            read_record: int = 0) -> SecureSession:
        """OPEN SECURE SESSION.  ``key_index`` selects the SAM key (1 debit, 2 load, 3 perso).

        The SAM diversifies on the card serial, produces the terminal challenge sent to the
        card, and the card's opening response seeds the SAM digest.  Every command until
        ``close_secure_session`` is included in the MAC.
        """
        if self.identity is None:
            raise CredentialError("select the application before opening a secure session")
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
        self._session = SecureSession(sam, key_index, card_challenge)
        return self._session

    def close_secure_session(self, ratify: bool = True) -> bool:
        """CLOSE SECURE SESSION: the SAM's terminal MAC is sent, the card's MAC verified."""
        if self._session is None or not self._session.open:
            raise CredentialError("no secure session is open")
        sess = self._session
        terminal_mac = sess.sam.digest_close()
        cmd = CommandAPDU(self.cla, INS_CLOSE_SECURE_SESSION, 0x80 if ratify else 0x00, 0x00, terminal_mac, 0)
        resp = transmit_apdu(self.channel.transmit, cmd).check(cmd.to_bytes(), allow_warnings=True)
        self._session = None
        card_mac = resp.data[:4]
        if not sess.sam.digest_authenticate(card_mac):
            raise CredentialError("card MAC not authenticated by the SAM - session is not trusted")
        return True

    def abort_secure_session(self) -> None:
        self._session = None

    def _require_session(self) -> None:
        if self._session is None or not self._session.open:
            raise CredentialError("this write must run inside an open secure session (open_secure_session first)")

    # -- writes (inside a session) --------------------------------------------------------
    def update_record(self, sfi: int, number: int, data: bytes) -> None:
        self._require_session()
        self._apdu(INS_UPDATE_RECORD, number, (sfi << 3) | P2_READ_ONE_RECORD, bytes(data))

    def write_record(self, sfi: int, number: int, data: bytes) -> None:
        self._require_session()
        self._apdu(INS_WRITE_RECORD, number, (sfi << 3) | P2_READ_ONE_RECORD, bytes(data))

    def append_record(self, sfi: int, data: bytes) -> None:
        self._require_session()
        self._apdu(INS_APPEND_RECORD, 0x00, (sfi & 0x1F) << 3, bytes(data))

    def increase_counter(self, sfi: int, counter: int, amount: int) -> bytes:
        self._require_session()
        return self._apdu(INS_INCREASE, counter, (sfi & 0x1F) << 3, amount.to_bytes(3, "big"), le=0).data

    def decrease_counter(self, sfi: int, counter: int, amount: int) -> bytes:
        self._require_session()
        return self._apdu(INS_DECREASE, counter, (sfi & 0x1F) << 3, amount.to_bytes(3, "big"), le=0).data

    # -- PIN ------------------------------------------------------------------------------
    def verify_pin(self, pin: bytes) -> None:
        self._apdu(INS_VERIFY_PIN, 0x00, 0x00, bytes(pin))

    # -- high level ------------------------------------------------------------------------
    def info(self) -> dict[str, str]:
        ident = self.identity or self.select_application()
        out = {"aid": ident.aid.hex().upper(), "serial": ident.serial_hex, "revision": str(ident.revision)}
        if ident.startup:
            out.update(ident.startup.describe())
        for sfi, recs in self.dump().items():
            out[f"EF {STANDARD_SFIS.get(sfi, hex(sfi))}"] = f"{len(recs)} record(s), {len(recs[0].data) if recs else 0} bytes each"
        return out


# alias fix for the forward reference above
CalypsosSam = CalypsoSam
SecureSession.__annotations__["sam"] = CalypsoSam
