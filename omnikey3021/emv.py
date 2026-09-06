"""EMV payment-card reading (EMVCo Level 2 application layer, read-only).

The OMNIKEY 3021 is EMVCo Level 1 certified (the electrical/protocol layer),
and can be switched to EMVCo mode (``ReaderConfig.set_operating_mode``).  This
module implements the read-only part of Level 2 that a kiosk or test bench
needs:

* PSE / PPSE directory reading and application listing (or AID probing)
* SELECT AID and FCI decoding (label, preferred name, language, PDOL)
* GET PROCESSING OPTIONS with a PDOL filled from ``TerminalData``
* AFL walk with READ RECORD, TLV decoding of every record
* GET DATA for ATC, PIN try counter, log format, and transaction log reading
* a tag dictionary (`EMV_TAGS`) and decoders (PAN, expiry, track 2, AIP, CVM list)

It does not perform transactions (no cryptogram / CDA / online authorisation).
"""

from __future__ import annotations

import datetime as _dt
import os
from dataclasses import dataclass, field

from .apdu import ResponseAPDU
from .channel import CardChannel
from .errors import CardError
from .iso7816 import Iso7816Card
from .tlv import TLV, decode, tlv

PSE = b"1PAY.SYS.DDF01"
PPSE = b"2PAY.SYS.DDF01"

KNOWN_AIDS: dict[str, str] = {
    "A0000000031010": "Visa Credit/Debit",
    "A0000000032010": "Visa Electron / V PAY",
    "A0000000032020": "V PAY",
    "A0000000033010": "Visa Interlink",
    "A0000000038010": "Visa Plus",
    "A0000000041010": "Mastercard Credit/Debit",
    "A0000000043060": "Maestro",
    "A0000000046000": "Cirrus",
    "A0000000050001": "Maestro UK",
    "A00000002501": "American Express",
    "A0000001523010": "Discover",
    "A0000000651010": "JCB",
    "A000000333010101": "UnionPay Debit",
    "A000000333010102": "UnionPay Credit",
    "A0000002771010": "Interac",
    "A0000000421010": "Cartes Bancaires",
    "A0000001211010": "Dankort",
    "A0000003591010028001": "girocard (German debit)",
    "A0000000980840": "US Common Debit",
    "A0000003241010": "Discover / Diners",
    "D27600002545500100": "girocard (ZKA)",
}

EMV_TAGS: dict[int, str] = {
    0x42: "Issuer Identification Number", 0x4F: "Application Identifier (AID)", 0x50: "Application Label",
    0x57: "Track 2 Equivalent Data", 0x5A: "Application PAN", 0x5F20: "Cardholder Name",
    0x5F24: "Application Expiration Date", 0x5F25: "Application Effective Date", 0x5F28: "Issuer Country Code",
    0x5F2A: "Transaction Currency Code", 0x5F2D: "Language Preference", 0x5F30: "Service Code",
    0x5F34: "Application PAN Sequence Number", 0x5F36: "Transaction Currency Exponent", 0x61: "Application Template",
    0x6F: "FCI Template", 0x70: "Record Template", 0x71: "Issuer Script Template 1", 0x72: "Issuer Script Template 2",
    0x73: "Directory Discretionary Template", 0x77: "Response Message Template Format 2",
    0x80: "Response Message Template Format 1", 0x82: "Application Interchange Profile", 0x83: "Command Template",
    0x84: "Dedicated File Name", 0x86: "Issuer Script Command", 0x87: "Application Priority Indicator",
    0x88: "Short File Identifier", 0x89: "Authorisation Code", 0x8A: "Authorisation Response Code",
    0x8C: "CDOL1", 0x8D: "CDOL2", 0x8E: "Cardholder Verification Method List", 0x8F: "CA Public Key Index",
    0x90: "Issuer Public Key Certificate", 0x91: "Issuer Authentication Data", 0x92: "Issuer Public Key Remainder",
    0x93: "Signed Static Application Data", 0x94: "Application File Locator", 0x95: "Terminal Verification Results",
    0x97: "TDOL", 0x98: "TC Hash Value", 0x99: "Transaction PIN Data", 0x9A: "Transaction Date",
    0x9B: "Transaction Status Information", 0x9C: "Transaction Type", 0x9D: "Directory Definition File Name",
    0x9F01: "Acquirer Identifier", 0x9F02: "Amount, Authorised", 0x9F03: "Amount, Other", 0x9F05: "Application Discretionary Data",
    0x9F06: "AID (terminal)", 0x9F07: "Application Usage Control", 0x9F08: "Application Version Number",
    0x9F09: "Application Version Number (terminal)", 0x9F0B: "Cardholder Name Extended", 0x9F0D: "IAC - Default",
    0x9F0E: "IAC - Denial", 0x9F0F: "IAC - Online", 0x9F10: "Issuer Application Data", 0x9F11: "Issuer Code Table Index",
    0x9F12: "Application Preferred Name", 0x9F13: "Last Online ATC Register", 0x9F14: "Lower Consecutive Offline Limit",
    0x9F17: "PIN Try Counter", 0x9F19: "Token Requestor ID", 0x9F1A: "Terminal Country Code", 0x9F1F: "Track 1 Discretionary Data",
    0x9F20: "Track 2 Discretionary Data", 0x9F23: "Upper Consecutive Offline Limit", 0x9F26: "Application Cryptogram",
    0x9F27: "Cryptogram Information Data", 0x9F2D: "ICC PIN Encipherment Public Key Certificate",
    0x9F2E: "ICC PIN Encipherment Public Key Exponent", 0x9F2F: "ICC PIN Encipherment Public Key Remainder",
    0x9F32: "Issuer Public Key Exponent", 0x9F33: "Terminal Capabilities", 0x9F34: "CVM Results",
    0x9F35: "Terminal Type", 0x9F36: "Application Transaction Counter", 0x9F37: "Unpredictable Number",
    0x9F38: "PDOL", 0x9F39: "POS Entry Mode", 0x9F40: "Additional Terminal Capabilities", 0x9F42: "Application Currency Code",
    0x9F44: "Application Currency Exponent", 0x9F45: "Data Authentication Code", 0x9F46: "ICC Public Key Certificate",
    0x9F47: "ICC Public Key Exponent", 0x9F48: "ICC Public Key Remainder", 0x9F49: "DDOL", 0x9F4A: "SDA Tag List",
    0x9F4B: "Signed Dynamic Application Data", 0x9F4C: "ICC Dynamic Number", 0x9F4D: "Log Entry", 0x9F4E: "Merchant Name and Location",
    0x9F4F: "Log Format", 0x9F51: "Application Currency Code (proprietary)", 0x9F5B: "Issuer Script Results",
    0x9F66: "Terminal Transaction Qualifiers", 0x9F6C: "Card Transaction Qualifiers", 0x9F6E: "Form Factor Indicator / Third Party Data",
    0x9F7F: "Card Production Life Cycle", 0xA5: "FCI Proprietary Template", 0xBF0C: "FCI Issuer Discretionary Data",
    0xDF01: "Proprietary", 0xC1: "Proprietary (Mastercard)",
}

AIP_BITS = [
    (1, 0x40, "SDA supported"), (1, 0x20, "DDA supported"), (1, 0x10, "Cardholder verification supported"),
    (1, 0x08, "Terminal risk management to be performed"), (1, 0x04, "Issuer authentication supported"),
    (1, 0x01, "CDA supported"), (2, 0x80, "EMV mode / MSD supported (contactless)"),
]

CVM_CODES = {
    0x00: "Fail CVM", 0x01: "Plaintext PIN by ICC", 0x02: "Enciphered PIN online", 0x03: "Plaintext PIN by ICC + signature",
    0x04: "Enciphered PIN by ICC", 0x05: "Enciphered PIN by ICC + signature", 0x1E: "Signature", 0x1F: "No CVM required",
}
CVM_CONDITIONS = {
    0x00: "Always", 0x01: "If unattended cash", 0x02: "If not (unattended cash, manual cash, purchase with cashback)",
    0x03: "If terminal supports the CVM", 0x04: "If manual cash", 0x05: "If purchase with cashback",
    0x06: "If transaction in application currency and under X", 0x07: "If transaction in application currency and over X",
    0x08: "If transaction in application currency and under Y", 0x09: "If transaction in application currency and over Y",
}


def tag_name(tag: int) -> str:
    return EMV_TAGS.get(tag, f"tag {tag:X}")


def decode_pan(value: bytes) -> str:
    return value.hex().upper().rstrip("F")


def decode_date(value: bytes) -> str:
    """YYMMDD (BCD) -> ISO date string; 5F24 expiry is the last day of the month when DD=00."""
    if len(value) != 3:
        return value.hex()
    yy, mm, dd = (int(value[0:1].hex()), int(value[1:2].hex()), int(value[2:3].hex()))
    year = 2000 + yy
    if dd == 0:
        dd = _last_day(year, mm) if 1 <= mm <= 12 else 1
    try:
        return _dt.date(year, mm, dd).isoformat()
    except ValueError:
        return value.hex()


def _last_day(year: int, month: int) -> int:
    nxt = _dt.date(year + (month == 12), (month % 12) + 1, 1)
    return (nxt - _dt.timedelta(days=1)).day


def decode_track2(value: bytes) -> dict[str, str]:
    digits = value.hex().upper().rstrip("F")
    if "D" not in digits:
        return {"raw": digits}
    pan, rest = digits.split("D", 1)
    return {"pan": pan, "expiry": f"20{rest[:2]}-{rest[2:4]}" if len(rest) >= 4 else "", "service_code": rest[4:7],
            "discretionary": rest[7:]}


def decode_aip(value: bytes) -> list[str]:
    out = []
    for byte_no, mask, text in AIP_BITS:
        if len(value) >= byte_no and value[byte_no - 1] & mask:
            out.append(text)
    return out


def decode_cvm_list(value: bytes) -> list[str]:
    if len(value) < 8:
        return []
    x = int.from_bytes(value[:4], "big")
    y = int.from_bytes(value[4:8], "big")
    out = [f"X={x} Y={y}"]
    for i in range(8, len(value) - 1, 2):
        code, cond = value[i], value[i + 1]
        method = CVM_CODES.get(code & 0x3F, f"CVM 0x{code & 0x3F:02X}")
        nxt = "apply next if unsuccessful" if code & 0x40 else "fail if unsuccessful"
        out.append(f"{method} [{CVM_CONDITIONS.get(cond, f'cond 0x{cond:02X}')}] ({nxt})")
    return out


def format_value(tag: int, value: bytes) -> str:
    if tag in (0x5A,):
        return decode_pan(value)
    if tag in (0x5F24, 0x5F25, 0x9A):
        return decode_date(value)
    if tag == 0x57:
        return str(decode_track2(value))
    if tag in (0x50, 0x9F12, 0x5F20, 0x5F2D, 0x9F4E, 0x84, 0x9D):
        try:
            text = value.decode("latin-1")
            if all(32 <= ord(c) < 127 for c in text) and tag != 0x84 and tag != 0x9D:
                return f"{text!r} ({value.hex().upper()})"
        except Exception:  # noqa: BLE001
            pass
    if tag == 0x82:
        return f"{value.hex().upper()} [{', '.join(decode_aip(value)) or 'no bits set'}]"
    if tag == 0x8E:
        return f"{value.hex().upper()} [{'; '.join(decode_cvm_list(value))}]"
    if tag in (0x9F36, 0x9F13, 0x9F17, 0x9F08):
        return f"{value.hex().upper()} ({int.from_bytes(value, 'big')})"
    return value.hex().upper()


def parse_dol(data: bytes) -> list[tuple[int, int]]:
    """Parse a Data Object List (tag, length pairs without values)."""
    out = []
    pos = 0
    while pos < len(data):
        tag = data[pos]
        pos += 1
        if (tag & 0x1F) == 0x1F:
            while pos < len(data):
                tag = (tag << 8) | data[pos]
                pos += 1
                if not data[pos - 1] & 0x80:
                    break
        if pos >= len(data):
            break
        length = data[pos]
        pos += 1
        out.append((tag, length))
    return out


@dataclass
class TerminalData:
    """Values a terminal supplies when the card's PDOL/CDOL asks for them."""

    country_code: int = 0x0840      # 9F1A (USA); e.g. 0x0276 Germany, 0x0124 Canada
    currency_code: int = 0x0840     # 5F2A
    amount: int = 0                 # 9F02 (numeric, 12 digits)
    amount_other: int = 0           # 9F03
    transaction_type: int = 0x00    # 9C
    terminal_type: int = 0x22       # 9F35 (attended, offline with online capability)
    terminal_capabilities: bytes = bytes.fromhex("E0F8C8")       # 9F33
    additional_capabilities: bytes = bytes.fromhex("6000F0A001")  # 9F40
    ttq: bytes = bytes.fromhex("36000000")                       # 9F66 (contactless)
    tvr: bytes = bytes(5)                                        # 95
    date: _dt.date | None = None                                 # 9A
    unpredictable_number: bytes | None = None                    # 9F37

    def value_for(self, tag: int, length: int) -> bytes:
        today = self.date or _dt.date.today()
        table: dict[int, bytes] = {
            0x9F1A: self.country_code.to_bytes(2, "big"),
            0x5F2A: self.currency_code.to_bytes(2, "big"),
            0x9F02: bytes.fromhex(f"{self.amount:012d}"),
            0x9F03: bytes.fromhex(f"{self.amount_other:012d}"),
            0x9C: bytes([self.transaction_type]),
            0x9F35: bytes([self.terminal_type]),
            0x9F33: self.terminal_capabilities,
            0x9F40: self.additional_capabilities,
            0x9F66: self.ttq,
            0x95: self.tvr,
            0x9A: bytes.fromhex(today.strftime("%y%m%d")),
            0x9F37: self.unpredictable_number or os.urandom(4),
            0x9F21: bytes.fromhex(_dt.datetime.now().strftime("%H%M%S")),
        }
        value = table.get(tag, b"")
        if len(value) < length:
            value = value.rjust(length, b"\x00") if tag in (0x9F02, 0x9F03) else value.ljust(length, b"\x00")
        return value[:length]

    def build_dol_data(self, dol: bytes) -> bytes:
        return b"".join(self.value_for(tag, length) for tag, length in parse_dol(dol))


@dataclass
class EmvApplication:
    aid: bytes
    label: str = ""
    priority: int | None = None
    preferred_name: str = ""
    extra: dict[int, bytes] = field(default_factory=dict)

    @property
    def scheme(self) -> str:
        hex_aid = self.aid.hex().upper()
        for prefix, name in KNOWN_AIDS.items():
            if hex_aid.startswith(prefix):
                return name
        return "unknown scheme"


@dataclass
class EmvRecord:
    sfi: int
    number: int
    raw: bytes
    tags: dict[int, bytes]
    used_for_offline_auth: bool = False


@dataclass
class EmvCardData:
    application: EmvApplication
    fci: dict[int, bytes]
    pdol: bytes
    aip: bytes
    afl: bytes
    records: list[EmvRecord]
    tags: dict[int, bytes]  # merged view of every tag found

    @property
    def pan(self) -> str | None:
        v = self.tags.get(0x5A)
        if v:
            return decode_pan(v)
        t2 = self.tags.get(0x57)
        return decode_track2(t2).get("pan") if t2 else None

    @property
    def expiry(self) -> str | None:
        v = self.tags.get(0x5F24)
        return decode_date(v) if v else None

    @property
    def cardholder_name(self) -> str | None:
        v = self.tags.get(0x5F20)
        return v.decode("latin-1").strip() if v else None

    def masked_pan(self) -> str | None:
        pan = self.pan
        if not pan:
            return None
        return pan[:6] + "*" * (len(pan) - 10) + pan[-4:] if len(pan) > 10 else "*" * len(pan)

    def describe(self, mask_pan: bool = True) -> list[str]:
        out = [f"Application: {self.application.aid.hex().upper()} ({self.application.scheme})"]
        if self.application.label:
            out.append(f"  Label: {self.application.label}")
        if self.application.preferred_name:
            out.append(f"  Preferred name: {self.application.preferred_name}")
        out.append(f"  PAN: {self.masked_pan() if mask_pan else self.pan}")
        out.append(f"  Expiry: {self.expiry}")
        if self.cardholder_name:
            out.append(f"  Cardholder: {self.cardholder_name}")
        out.append(f"  AIP: {format_value(0x82, self.aip)}")
        out.append(f"  AFL: {self.afl.hex().upper()}  ({len(self.records)} records)")
        for tag in sorted(self.tags):
            if tag in (0x5A, 0x57) and mask_pan:
                continue
            out.append(f"  {tag:X} {tag_name(tag)}: {format_value(tag, self.tags[tag])}")
        return out


def _flatten(nodes: list[TLV], into: dict[int, bytes]) -> None:
    for n in nodes:
        if n.children:
            _flatten(n.children, into)
        else:
            into[n.tag] = n.value


class EmvCard:
    """Read-only EMV application layer on top of an ISO 7816 channel."""

    def __init__(self, channel: CardChannel, terminal: TerminalData | None = None):
        self.iso = Iso7816Card(channel)
        self.terminal = terminal or TerminalData()
        self.last_fci: dict[int, bytes] = {}

    # -- application discovery ---------------------------------------------------
    def list_applications(self, contactless_pse: bool = False, probe: bool = True) -> list[EmvApplication]:
        apps: list[EmvApplication] = []
        try:
            apps = self._read_pse(PPSE if contactless_pse else PSE)
        except CardError:
            apps = []
        if not apps and probe:
            for hex_aid in KNOWN_AIDS:
                aid = bytes.fromhex(hex_aid)
                try:
                    fci = self.iso.select_aid(aid)
                except CardError:
                    continue
                app = EmvApplication(aid)
                flat: dict[int, bytes] = {}
                if fci.template:
                    _flatten([fci.template], flat)
                app.label = flat.get(0x50, b"").decode("latin-1", "replace")
                app.preferred_name = flat.get(0x9F12, b"").decode("latin-1", "replace")
                apps.append(app)
        apps.sort(key=lambda a: (a.priority if a.priority is not None else 99))
        return apps

    def _read_pse(self, name: bytes) -> list[EmvApplication]:
        fci = self.iso.select_aid(name)
        flat: dict[int, bytes] = {}
        if fci.template:
            _flatten([fci.template], flat)
        apps: list[EmvApplication] = []
        if name == PPSE:
            # PPSE lists applications directly in BF0C / 61 templates
            for node in (fci.template.find_deep(0xBF0C).children if fci.template and fci.template.find_deep(0xBF0C) else []):
                if node.tag == 0x61:
                    apps.append(self._app_from_template(node))
            return apps
        sfi_raw = flat.get(0x88)
        if not sfi_raw:
            return apps
        sfi = sfi_raw[0]
        for n in range(1, 32):
            try:
                rec = self.iso.read_record(n, sfi=sfi)
            except CardError as exc:
                if exc.sw in (0x6A83, 0x6A82, 0x6982):
                    break
                raise
            for node in decode(rec):
                items = node.children if node.tag == 0x70 else [node]
                for item in items:
                    if item.tag == 0x61:
                        apps.append(self._app_from_template(item))
        return apps

    @staticmethod
    def _app_from_template(node: TLV) -> EmvApplication:
        flat: dict[int, bytes] = {}
        _flatten(node.children, flat)
        app = EmvApplication(flat.get(0x4F, b""))
        app.label = flat.get(0x50, b"").decode("latin-1", "replace")
        app.preferred_name = flat.get(0x9F12, b"").decode("latin-1", "replace")
        if 0x87 in flat and flat[0x87]:
            app.priority = flat[0x87][0] & 0x0F
        app.extra = {k: v for k, v in flat.items() if k not in (0x4F, 0x50, 0x9F12, 0x87)}
        return app

    # -- application selection / GPO ---------------------------------------------------
    def select_application(self, aid: bytes) -> dict[int, bytes]:
        fci = self.iso.select_aid(aid)
        flat: dict[int, bytes] = {}
        if fci.template:
            _flatten([fci.template], flat)
        self.last_fci = flat
        return flat

    def get_processing_options(self, pdol: bytes = b"") -> tuple[bytes, bytes]:
        """GPO; returns (AIP, AFL)."""
        data = tlv(0x83, self.terminal.build_dol_data(pdol) if pdol else b"").encode()
        resp = self.iso.send(0xA8, 0x00, 0x00, data, 256, cla=0x80)
        return self.parse_gpo(resp)

    @staticmethod
    def parse_gpo(resp: ResponseAPDU) -> tuple[bytes, bytes]:
        nodes = decode(resp.data)
        if not nodes:
            raise CardError(0x6F, 0x00, "empty GPO response")
        node = nodes[0]
        if node.tag == 0x80:
            return node.value[:2], node.value[2:]
        if node.tag == 0x77:
            flat: dict[int, bytes] = {}
            _flatten(node.children, flat)
            return flat.get(0x82, b""), flat.get(0x94, b"")
        raise CardError(0x6F, 0x00, f"unexpected GPO template {node.tag:X}")

    def read_afl_records(self, afl: bytes) -> list[EmvRecord]:
        records: list[EmvRecord] = []
        for i in range(0, len(afl) - 3, 4):
            sfi = afl[i] >> 3
            first, last, auth_count = afl[i + 1], afl[i + 2], afl[i + 3]
            for n in range(first, last + 1):
                try:
                    raw = self.iso.read_record(n, sfi=sfi)
                except CardError as exc:
                    if exc.sw in (0x6A83, 0x6A82):
                        continue
                    raise
                tags: dict[int, bytes] = {}
                try:
                    _flatten(decode(raw), tags)
                except ValueError:
                    pass
                records.append(EmvRecord(sfi, n, raw, tags, n - first < auth_count))
        return records

    def read_application(self, aid: bytes | EmvApplication) -> EmvCardData:
        app = aid if isinstance(aid, EmvApplication) else EmvApplication(bytes(aid))
        fci = self.select_application(app.aid)
        if not app.label:
            app.label = fci.get(0x50, b"").decode("latin-1", "replace")
        if not app.preferred_name:
            app.preferred_name = fci.get(0x9F12, b"").decode("latin-1", "replace")
        pdol = fci.get(0x9F38, b"")
        aip, afl = self.get_processing_options(pdol)
        records = self.read_afl_records(afl)
        merged: dict[int, bytes] = {}
        for r in records:
            merged.update(r.tags)
        return EmvCardData(app, fci, pdol, aip, afl, records, merged)

    # -- GET DATA ------------------------------------------------------------------------------
    def _get_data(self, tag: int) -> bytes | None:
        try:
            resp = self.iso.send(0xCA, (tag >> 8) & 0xFF, tag & 0xFF, le=256, cla=0x80)
        except CardError:
            return None
        nodes = decode(resp.data) if resp.data else []
        return nodes[0].value if nodes else resp.data

    def transaction_counter(self) -> int | None:
        v = self._get_data(0x9F36)
        return int.from_bytes(v, "big") if v else None

    def last_online_atc(self) -> int | None:
        v = self._get_data(0x9F13)
        return int.from_bytes(v, "big") if v else None

    def pin_try_counter(self) -> int | None:
        v = self._get_data(0x9F17)
        return v[0] if v else None

    def log_format(self) -> list[tuple[int, int]] | None:
        v = self._get_data(0x9F4F)
        return parse_dol(v) if v else None

    def transaction_log(self) -> list[dict[str, str]]:
        """Read the transaction log (Log Entry 9F4D from the FCI + Log Format 9F4F)."""
        entry = self.last_fci.get(0x9F4D)
        fmt = self.log_format()
        if not entry or len(entry) < 2 or not fmt:
            return []
        sfi, count = entry[0], entry[1]
        out = []
        for n in range(1, count + 1):
            try:
                raw = self.iso.read_record(n, sfi=sfi)
            except CardError:
                break
            row: dict[str, str] = {}
            pos = 0
            for tag, length in fmt:
                row[tag_name(tag)] = format_value(tag, raw[pos : pos + length])
                pos += length
            out.append(row)
        return out
