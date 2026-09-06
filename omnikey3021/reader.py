"""High level access to an OMNIKEY 3021 through PC/SC.

::

    from omnikey3021 import OmnikeyReader

    reader = OmnikeyReader()             # first OMNIKEY reader found
    reader.wait_for_card()
    with reader.connect() as card:       # CardSession implements CardChannel
        print(card.parsed_atr.describe())
        print(card.transmit(bytes.fromhex("00A4040000")))
"""

from __future__ import annotations

import logging
import struct
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from . import pcsc_constants as C
from .apdu import CommandAPDU, ResponseAPDU, transmit_apdu
from .atr import ATR, parse_atr
from .errors import NoCardError, OmnikeyError, PCSCError, ReaderNotFoundError
from .pcsc import Card, Context, ReaderState, find_omnikey_readers

log = logging.getLogger(__name__)


@dataclass
class Feature:
    tag: int
    name: str
    control_code: int


class CardSession:
    """An open connection to the card in an OMNIKEY reader (implements CardChannel)."""

    def __init__(self, card: Card, reader_name: str):
        self._card = card
        self.reader_name = reader_name
        self._features: dict[int, Feature] | None = None
        self.trace = False  # print every APDU exchange when True

    # -- CardChannel -----------------------------------------------------------
    @property
    def atr(self) -> bytes:
        return self._card.atr

    @property
    def protocol(self) -> int:
        return self._card.protocol

    @property
    def protocol_name(self) -> str:
        return C.PROTOCOL_NAMES.get(self.protocol, f"0x{self.protocol:X}")

    @property
    def parsed_atr(self) -> ATR:
        return parse_atr(self.atr)

    def transmit(self, data: bytes) -> bytes:
        if self.protocol == C.SCARD_PROTOCOL_UNDEFINED:
            raise NoCardError("connected in DIRECT mode: no card protocol negotiated; use control() or reconnect()")
        t0 = time.perf_counter()
        resp = self._card.transmit(bytes(data))
        if self.trace:
            dt = (time.perf_counter() - t0) * 1000
            print(f">> {bytes(data).hex(' ').upper()}\n<< {resp.hex(' ').upper()}  ({dt:.1f} ms)")
        log.debug("APDU >> %s", bytes(data).hex(" ").upper())
        log.debug("APDU << %s", resp.hex(" ").upper())
        return resp

    def control(self, code: int, data: bytes = b"") -> bytes:
        resp = self._card.control(code, bytes(data))
        if self.trace:
            print(f"CTL 0x{code:08X} >> {bytes(data).hex(' ').upper()}\n<< {resp.hex(' ').upper()}")
        return resp

    # -- convenience -------------------------------------------------------------
    def apdu(self, command: CommandAPDU | bytes, **kw) -> ResponseAPDU:
        """Send an APDU with automatic 61xx/6Cxx handling."""
        return transmit_apdu(self.transmit, command, **kw)

    def status(self):
        return self._card.status()

    def reconnect(self, reset: bool = True, protocols: int = C.SCARD_PROTOCOL_ANY,
                  share_mode: int = C.SCARD_SHARE_SHARED) -> int:
        """Re-negotiate the connection; ``reset=True`` performs a warm reset of the card."""
        return self._card.reconnect(share_mode, protocols, C.SCARD_RESET_CARD if reset else C.SCARD_LEAVE_CARD)

    def disconnect(self, disposition: int = C.SCARD_LEAVE_CARD) -> None:
        self._card.disconnect(disposition)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.disconnect()

    @contextmanager
    def transaction(self, disposition: int = C.SCARD_LEAVE_CARD) -> Iterator["CardSession"]:
        """Hold the reader exclusively for a sequence of commands."""
        self._card.begin_transaction()
        try:
            yield self
        finally:
            try:
                self._card.end_transaction(disposition)
            except OmnikeyError:
                pass

    # -- reader attributes (SCardGetAttrib) ---------------------------------------
    def get_attrib(self, attr: int) -> bytes:
        return self._card.get_attrib(attr)

    def attributes(self) -> dict[str, str]:
        """Read every standard attribute the driver exposes; unsupported ones are skipped."""
        out: dict[str, str] = {}
        for attr, name in C.ATTRIBUTE_NAMES.items():
            try:
                value = self.get_attrib(attr)
            except OmnikeyError:
                continue
            out[name] = _format_attribute(attr, value)
        return out

    # -- PC/SC part 10 features and CCID escape -------------------------------------
    def features(self) -> dict[int, Feature]:
        """Query CM_IOCTL_GET_FEATURE_REQUEST (PC/SC v2 part 10)."""
        if self._features is None:
            feats: dict[int, Feature] = {}
            try:
                raw = self.control(C.CM_IOCTL_GET_FEATURE_REQUEST)
            except OmnikeyError as exc:
                log.debug("feature request failed: %s", exc)
                raw = b""
            pos = 0
            while pos + 6 <= len(raw):
                tag, length = raw[pos], raw[pos + 1]
                value = raw[pos + 2 : pos + 2 + length]
                if length == 4:
                    code = struct.unpack(">I", value)[0]
                    feats[tag] = Feature(tag, C.FEATURE_NAMES.get(tag, f"FEATURE_0x{tag:02X}"), code)
                pos += 2 + length
            self._features = feats
        return self._features

    def escape_control_code(self) -> int:
        """Control code for CCID escape: FEATURE_CCID_ESC_COMMAND if advertised, else SCARD_CTL_CODE(3500)."""
        feat = self.features().get(C.FEATURE_CCID_ESC_COMMAND)
        return feat.control_code if feat else C.IOCTL_CCID_ESCAPE

    def escape(self, payload: bytes) -> bytes:
        """Send a CCID escape command (works without a card, SCARD_SHARE_DIRECT).

        On Windows with the Microsoft CCID driver the registry value
        ``EscapeCommandEnable`` must be set (PLT-03099 appendix A).
        """
        return self.control(self.escape_control_code(), payload)

    def tlv_properties(self) -> dict[str, object]:
        """PC/SC part 10 GET_TLV_PROPERTIES: USB VID/PID, firmware id, max APDU size ... (if advertised)."""
        from .ccid import parse_tlv_properties

        feat = self.features().get(C.FEATURE_GET_TLV_PROPERTIES)
        if feat is None:
            return {}
        try:
            return parse_tlv_properties(self.control(feat.control_code))
        except OmnikeyError as exc:
            log.debug("GET_TLV_PROPERTIES failed: %s", exc)
            return {}

    def legacy_firmware_version(self) -> bytes | None:
        """CM_IOCTL_GET_FW_VERSION (3001) - only answered by the legacy HID OMNIKEY driver."""
        try:
            return self.control(C.CM_IOCTL_GET_FW_VERSION)
        except OmnikeyError:
            return None


def _format_attribute(attr: int, value: bytes) -> str:
    text_attrs = {
        C.SCARD_ATTR_VENDOR_NAME, C.SCARD_ATTR_VENDOR_IFD_TYPE, C.SCARD_ATTR_VENDOR_IFD_SERIAL_NO,
        C.SCARD_ATTR_DEVICE_FRIENDLY_NAME, C.SCARD_ATTR_DEVICE_SYSTEM_NAME,
    }
    if attr in text_attrs:
        return value.rstrip(b"\x00").decode("utf-8", "replace")
    if attr == C.SCARD_ATTR_VENDOR_IFD_VERSION and len(value) >= 4:
        v = int.from_bytes(value[:4], "little")
        return f"{(v >> 24) & 0xFF}.{(v >> 16) & 0xFF} build {v & 0xFFFF} (raw {value.hex().upper()})"
    if attr == C.SCARD_ATTR_ATR_STRING:
        return value.hex(" ").upper()
    if attr == C.SCARD_ATTR_CURRENT_PROTOCOL_TYPE and len(value) >= 4:
        return C.PROTOCOL_NAMES.get(int.from_bytes(value[:4], "little"), value.hex().upper())
    if attr == C.SCARD_ATTR_ICC_PRESENCE and value:
        return {0: "absent", 1: "present (not swallowed)", 2: "present (swallowed)", 4: "confiscated"}.get(
            value[0], str(value[0]))
    if len(value) in (1, 2, 4) and attr not in text_attrs:
        return str(int.from_bytes(value, "little"))
    return value.hex(" ").upper()


class OmnikeyReader:
    """Discovery and connection management for one OMNIKEY reader."""

    def __init__(self, name: str | None = None, context: Context | None = None, pattern: str | None = None,
                 scope: int = C.SCARD_SCOPE_USER):
        self.context = context or Context(scope)
        self._owns_context = context is None
        if name is None:
            candidates = find_omnikey_readers(self.context.list_readers(), pattern)
            if not candidates:
                all_readers = self.context.list_readers()
                hint = f" Readers present: {all_readers}" if all_readers else " No PC/SC readers present at all."
                raise ReaderNotFoundError("no OMNIKEY reader found." + hint)
            name = candidates[0]
        self.name = name

    @classmethod
    def list(cls, pattern: str | None = None, all_readers: bool = False, scope: int = C.SCARD_SCOPE_USER) -> list[str]:
        with Context(scope) as ctx:
            readers = ctx.list_readers()
        return readers if all_readers else find_omnikey_readers(readers, pattern)

    def close(self) -> None:
        if self._owns_context:
            self.context.release()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- card presence -----------------------------------------------------------
    def state(self) -> ReaderState:
        return self.context.get_status_change([self.name], None, 0)[0]

    def is_card_present(self) -> bool:
        return self.state().present

    def wait_for_card(self, timeout_s: float | None = None) -> ReaderState:
        ms = C.INFINITE if timeout_s is None else int(timeout_s * 1000)
        return self.context.wait_for_card(self.name, ms)

    def wait_for_removal(self, timeout_s: float | None = None) -> ReaderState:
        ms = C.INFINITE if timeout_s is None else int(timeout_s * 1000)
        return self.context.wait_for_removal(self.name, ms)

    # -- connections -----------------------------------------------------------------
    def connect(self, protocols: int = C.SCARD_PROTOCOL_ANY, share_mode: int = C.SCARD_SHARE_SHARED,
                retries: int = 3, retry_delay_s: float = 0.3) -> CardSession:
        """Connect to the inserted card.  ``protocols`` may force T=0 or T=1."""
        last: Exception | None = None
        for _ in range(max(1, retries)):
            try:
                card = self.context.connect(self.name, share_mode, protocols)
                return CardSession(card, self.name)
            except PCSCError as exc:
                last = exc
                # The reader may still be powering the card right after insertion.
                if exc.code in (C.SCARD_E_SHARING_VIOLATION, C.SCARD_W_UNPOWERED_CARD, C.SCARD_E_PROTO_MISMATCH):
                    time.sleep(retry_delay_s)
                    continue
                raise
        assert last is not None
        raise last

    def connect_direct(self) -> CardSession:
        """Connect to the reader itself (no card required) for SCardControl / escape commands."""
        card = self.context.connect(self.name, C.SCARD_SHARE_DIRECT, C.SCARD_PROTOCOL_UNDEFINED)
        return CardSession(card, self.name)
