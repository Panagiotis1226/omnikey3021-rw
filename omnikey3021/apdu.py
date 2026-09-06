"""ISO/IEC 7816-4 APDU construction, response parsing and status-word decoding.

Supports the short and extended encodings described in chapter 7 of the HID
OMNIKEY Contact Smart Card Readers Software Developer Guide (PLT-03099):

* Case 1: CLA INS P1 P2
* Case 2: CLA INS P1 P2 Le
* Case 3: CLA INS P1 P2 Lc Data
* Case 4: CLA INS P1 P2 Lc Data Le

Extended length (T=1 cards with the reader in Extended APDU exchange level):
Lc = 00 hi lo, Le = (00) hi lo.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .errors import CardError, OmnikeyError

Transmit = Callable[[bytes], bytes]


@dataclass(frozen=True)
class CommandAPDU:
    cla: int
    ins: int
    p1: int = 0
    p2: int = 0
    data: bytes = b""
    le: int | None = None  # None = no Le field; 0 or 256 = "max short"; 65536 = "max extended"
    extended: bool = False

    def __post_init__(self):
        for name in ("cla", "ins", "p1", "p2"):
            v = getattr(self, name)
            if not 0 <= v <= 0xFF:
                raise ValueError(f"{name} must be a byte, got {v}")
        if len(self.data) > 0xFFFF:
            raise ValueError("command data exceeds 65535 bytes")
        if len(self.data) > 0xFF and not self.extended:
            object.__setattr__(self, "extended", True)
        if self.le is not None and self.le > 256 and not self.extended:
            object.__setattr__(self, "extended", True)

    @property
    def case(self) -> int:
        if not self.data and self.le is None:
            return 1
        if not self.data:
            return 2
        if self.le is None:
            return 3
        return 4

    def to_bytes(self) -> bytes:
        out = bytes([self.cla, self.ins, self.p1, self.p2])
        lc_present = bool(self.data)
        if self.extended:
            if lc_present:
                out += b"\x00" + len(self.data).to_bytes(2, "big") + self.data
            if self.le is not None:
                le = 0 if self.le in (0, 65536) else self.le
                if le > 0xFFFF:
                    raise ValueError("Le exceeds 65536")
                out += (b"" if lc_present else b"\x00") + le.to_bytes(2, "big")
        else:
            if lc_present:
                out += bytes([len(self.data)]) + self.data
            if self.le is not None:
                le = 0 if self.le in (0, 256) else self.le
                if le > 0xFF:
                    raise ValueError("Le exceeds 256 in short APDU")
                out += bytes([le])
        return out

    def with_le(self, le: int) -> "CommandAPDU":
        return CommandAPDU(self.cla, self.ins, self.p1, self.p2, self.data, le, self.extended)

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def hex(self) -> str:
        return self.to_bytes().hex().upper()

    @classmethod
    def parse(cls, raw: bytes) -> "CommandAPDU":
        """Parse a raw command APDU (short or extended) back into fields."""
        raw = bytes(raw)
        if len(raw) < 4:
            raise ValueError("APDU shorter than 4 bytes")
        cla, ins, p1, p2 = raw[:4]
        body = raw[4:]
        if not body:
            return cls(cla, ins, p1, p2)
        if len(body) == 1:
            return cls(cla, ins, p1, p2, le=body[0] or 256)
        if body[0] == 0x00 and len(body) >= 3:
            # extended
            if len(body) == 3:
                le = int.from_bytes(body[1:3], "big") or 65536
                return cls(cla, ins, p1, p2, le=le, extended=True)
            lc = int.from_bytes(body[1:3], "big")
            data = body[3 : 3 + lc]
            rest = body[3 + lc :]
            if len(data) != lc:
                raise ValueError("Lc does not match data length")
            if not rest:
                return cls(cla, ins, p1, p2, data, extended=True)
            if len(rest) == 2:
                return cls(cla, ins, p1, p2, data, int.from_bytes(rest, "big") or 65536, extended=True)
            raise ValueError("malformed extended APDU")
        lc = body[0]
        data = body[1 : 1 + lc]
        rest = body[1 + lc :]
        if len(data) != lc:
            raise ValueError("Lc does not match data length")
        if not rest:
            return cls(cla, ins, p1, p2, data)
        if len(rest) == 1:
            return cls(cla, ins, p1, p2, data, rest[0] or 256)
        raise ValueError("malformed short APDU (trailing bytes)")


@dataclass(frozen=True)
class ResponseAPDU:
    data: bytes
    sw1: int
    sw2: int

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ResponseAPDU":
        raw = bytes(raw)
        if len(raw) < 2:
            raise ValueError(f"response shorter than 2 bytes: {raw.hex()}")
        return cls(raw[:-2], raw[-2], raw[-1])

    @property
    def sw(self) -> int:
        return (self.sw1 << 8) | self.sw2

    @property
    def ok(self) -> bool:
        return self.sw == 0x9000

    @property
    def warning(self) -> bool:
        return self.sw1 in (0x62, 0x63)

    @property
    def description(self) -> str:
        return describe_sw(self.sw1, self.sw2)

    def check(self, command: bytes | None = None, allow_warnings: bool = False) -> "ResponseAPDU":
        if self.ok or (allow_warnings and self.warning):
            return self
        raise CardError(self.sw1, self.sw2, command=command)

    def to_bytes(self) -> bytes:
        return self.data + bytes([self.sw1, self.sw2])

    def hex(self) -> str:
        return self.to_bytes().hex().upper()


# ---------------------------------------------------------------------------
# Status words (ISO 7816-4 + PC/SC part 3 memory-card meanings from PLT-03099)
# ---------------------------------------------------------------------------
_SW_EXACT = {
    0x9000: "Success",
    0x6200: "Warning: no information given (state of non-volatile memory unchanged)",
    0x6281: "Warning: part of returned data may be corrupted",
    0x6282: "Warning: end of file/record reached before reading Le bytes",
    0x6283: "Warning: selected file invalidated / deactivated",
    0x6284: "Warning: FCI not formatted according to ISO 7816-4",
    0x6285: "Warning: selected file in termination state",
    0x6286: "Warning: no input data available from a sensor on the card",
    0x6300: "Warning: verification failed / no information given",
    0x6381: "Warning: file filled up by the last write",
    0x6400: "Execution error: state of non-volatile memory unchanged",
    0x6401: "Execution error: immediate response required by the card",
    0x6500: "Execution error: state of non-volatile memory changed",
    0x6581: "Execution error: memory failure (unsuccessful writing)",
    0x6600: "Security-related issue",
    0x6700: "Wrong length (Lc/Le)",
    0x6800: "Functions in CLA not supported",
    0x6881: "Logical channel not supported",
    0x6882: "Secure messaging not supported",
    0x6883: "Last command of the chain expected",
    0x6884: "Command chaining not supported",
    0x6900: "Command not allowed",
    0x6981: "Command incompatible with file structure",
    0x6982: "Security status not satisfied (PIN/PSC not presented)",
    0x6983: "Authentication / verify method blocked",
    0x6984: "Reference data not usable",
    0x6985: "Conditions of use not satisfied",
    0x6986: "Command not allowed (no current EF)",
    0x6987: "Expected secure messaging data objects missing",
    0x6988: "Incorrect secure messaging data objects / unknown card protocol",
    0x6A00: "Wrong parameters P1-P2",
    0x6A80: "Incorrect parameters in the command data field",
    0x6A81: "Function not supported",
    0x6A82: "File or application not found / addressed block or byte does not exist",
    0x6A83: "Record not found",
    0x6A84: "Not enough memory space in the file",
    0x6A85: "Lc inconsistent with TLV structure",
    0x6A86: "Incorrect parameters P1-P2",
    0x6A87: "Lc inconsistent with P1-P2",
    0x6A88: "Referenced data or reference data not found",
    0x6A89: "File already exists",
    0x6A8A: "DF name already exists",
    0x6B00: "Wrong parameters P1-P2 (offset outside file)",
    0x6D00: "Instruction code not supported or invalid",
    0x6E00: "Class not supported",
    0x6F00: "No precise diagnosis / unknown or unsupported card protocol",
}


def describe_sw(sw1: int, sw2: int) -> str:
    sw = (sw1 << 8) | sw2
    if sw in _SW_EXACT:
        return _SW_EXACT[sw]
    if sw1 == 0x61:
        return f"{sw2} response bytes still available (use GET RESPONSE)"
    if sw1 == 0x6C:
        return f"Wrong Le; exact length is {sw2}"
    if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        return f"Verification failed; {sw2 & 0x0F} retries remaining"
    if sw1 == 0x62:
        return "Warning: state of non-volatile memory unchanged"
    if sw1 == 0x63:
        return "Warning: state of non-volatile memory changed"
    if sw1 == 0x64:
        return "Execution error: state of non-volatile memory unchanged"
    if sw1 == 0x65:
        return "Execution error: state of non-volatile memory changed"
    if sw1 == 0x66:
        return "Security-related issue"
    if sw1 == 0x68:
        return "Functions in CLA not supported"
    if sw1 == 0x69:
        return "Command not allowed"
    if sw1 == 0x6A:
        return "Wrong parameters P1-P2"
    if sw1 == 0x90:
        return "Success (proprietary SW2)"
    if sw1 == 0x91:
        return "Success (GSM/JavaCard proprietary, more data)"
    if sw1 in (0x92, 0x94, 0x98):
        return "Proprietary (GSM 11.11) status"
    return "Unknown status word"


def transmit_apdu(transmit: Transmit, command: CommandAPDU | bytes, *, auto_get_response: bool = True,
                  auto_fix_le: bool = True, max_rounds: int = 64) -> ResponseAPDU:
    """Send an APDU handling the T=0 conventions transparently.

    * ``6C xx``  -> the command is re-issued with Le = xx.
    * ``61 xx``  -> GET RESPONSE is issued repeatedly and the data concatenated.
    * an empty response to a case-4 command (seen with some CCID drivers, e.g. macOS,
      when a T=0 card has data to return) -> the command is re-sent as case 3 and the
      data fetched with GET RESPONSE.
    """
    cmd = command if isinstance(command, CommandAPDU) else CommandAPDU.parse(bytes(command))
    raw = transmit(cmd.to_bytes())
    if len(raw) < 2 and cmd.data and cmd.le is not None:
        # Some CCID drivers (seen on macOS) swallow the response to a case-4 command
        # when a T=0 card has data: resend as case 3, then fetch with GET RESPONSE.
        case3 = CommandAPDU(cmd.cla, cmd.ins, cmd.p1, cmd.p2, cmd.data, None, cmd.extended)
        raw = transmit(case3.to_bytes())
        if raw[-2:] == b"\x90\x00" and auto_get_response:
            fetched = transmit(CommandAPDU(cmd.cla & 0x03, 0xC0, 0, 0, le=cmd.le or 256).to_bytes())
            if len(fetched) >= 2:
                raw = fetched
        elif len(raw) >= 2 and raw[-2] == 0x6C:
            raw = transmit(CommandAPDU(cmd.cla, cmd.ins, cmd.p1, cmd.p2, cmd.data, raw[-1] or 256, cmd.extended).to_bytes())
    if len(raw) < 2:
        raise OmnikeyError(
            f"empty response to {cmd.hex()} (the card returned no data). "
            "The card may not support this command, or selection by this method. "
            "Try --cla 94 (legacy Calypso), a different --protocol, or `omnikey3021 calypso info`."
        )
    resp = ResponseAPDU.from_bytes(raw)
    rounds = 0
    if auto_fix_le and resp.sw1 == 0x6C and not resp.data:
        cmd = cmd.with_le(resp.sw2 or 256)
        resp = ResponseAPDU.from_bytes(transmit(cmd.to_bytes()))
    data = resp.data
    while auto_get_response and resp.sw1 == 0x61 and rounds < max_rounds:
        rounds += 1
        get_resp = CommandAPDU(cmd.cla & 0x03, 0xC0, 0x00, 0x00, le=resp.sw2 or 256)
        fetched = transmit(get_resp.to_bytes())
        if len(fetched) < 2:
            raise OmnikeyError(f"empty response to GET RESPONSE after {resp.sw:04X}")
        resp = ResponseAPDU.from_bytes(fetched)
        data += resp.data
    return ResponseAPDU(data, resp.sw1, resp.sw2)


def hexstr(data: bytes, sep: str = " ") -> str:
    return sep.join(f"{b:02X}" for b in bytes(data))


def parse_hex(text: str) -> bytes:
    """Parse "FF B0 00 00 10", "ffb0000010", "FF:B0" or "0xFF,0xB0" into bytes."""
    cleaned = (
        text.replace("0x", "").replace("0X", "").replace(",", " ").replace(":", " ").replace("-", " ")
    )
    cleaned = "".join(cleaned.split())
    if len(cleaned) % 2:
        raise ValueError(f"odd number of hex digits in {text!r}")
    return bytes.fromhex(cleaned)
