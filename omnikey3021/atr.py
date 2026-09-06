"""ISO/IEC 7816-3 Answer-To-Reset parsing, plus memory-card recognition.

Asynchronous cards return a real ATR.  For synchronous (memory) cards the
OMNIKEY reader composes a pseudo ATR (PLT-03099 section 5.1: "If there is no
ATR (i.e. some I2C cards), the state of lines is checked and the fake ATR
composed").  Two-wire (SLE 4432/4442) and three-wire (SLE 4418/4428) cards
answer a 4-byte synchronous header; readers conventionally wrap it as
``3B 04 <header>``.  The tables below recognise both forms.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# TA1 clock-rate conversion factor Fi and max frequency (MHz) by high nibble
FI_TABLE = [372, 372, 558, 744, 1116, 1488, 1860, None, None, 512, 768, 1024, 1536, 2048, None, None]
FMAX_TABLE = [4, 5, 6, 8, 12, 16, 20, None, None, 5, 7.5, 10, 15, 20, None, None]
# TA1 baud-rate adjustment factor Di by low nibble
DI_TABLE = [None, 1, 2, 4, 8, 16, 32, 64, 12, 20, None, None, None, None, None, None]


class CardKind(str, Enum):
    ASYNC = "asynchronous"        # CPU / ISO 7816-4 card, T=0 or T=1
    SLE4442 = "SLE4432/SLE4442"   # 2-wire bus protocol, 256 bytes
    SLE4428 = "SLE4418/SLE4428"   # 3-wire bus protocol, 1024 bytes
    I2C = "I2C"                   # 2-wire serial EEPROM (AT24Cxx etc.)
    UNKNOWN_SYNC = "unknown synchronous"
    UNKNOWN = "unknown"


# Synchronous card headers (the 4 bytes a 2WBP/3WBP card returns after reset).
# The first byte encodes protocol type and structure; the second the memory
# organisation (ISO 7816-10).  Values commonly observed in the field:
SYNC_HEADERS = {
    bytes.fromhex("A2131091"): CardKind.SLE4442,  # SLE4442 / SLE4432 / SLE5542
    bytes.fromhex("A2131090"): CardKind.SLE4442,
    bytes.fromhex("92231091"): CardKind.SLE4428,  # SLE4428 / SLE4418 / SLE5528
    bytes.fromhex("92231090"): CardKind.SLE4428,
}


@dataclass
class ATR:
    raw: bytes
    ts: int = 0
    t0: int = 0
    interface_bytes: dict[str, int] = field(default_factory=dict)  # "TA1", "TB1", ...
    protocols: list[int] = field(default_factory=list)
    historical: bytes = b""
    tck: int | None = None
    tck_valid: bool | None = None
    kind: CardKind = CardKind.UNKNOWN
    warnings: list[str] = field(default_factory=list)

    # ---- derived -----------------------------------------------------------
    @property
    def direct_convention(self) -> bool:
        return self.ts == 0x3B

    @property
    def supports_t0(self) -> bool:
        return 0 in self.protocols or (not self.protocols and self.kind == CardKind.ASYNC)

    @property
    def supports_t1(self) -> bool:
        return 1 in self.protocols

    @property
    def is_memory_card(self) -> bool:
        return self.kind in (CardKind.SLE4442, CardKind.SLE4428, CardKind.I2C, CardKind.UNKNOWN_SYNC)

    @property
    def fi(self) -> int | None:
        ta1 = self.interface_bytes.get("TA1", 0x11)
        return FI_TABLE[ta1 >> 4]

    @property
    def di(self) -> int | None:
        ta1 = self.interface_bytes.get("TA1", 0x11)
        return DI_TABLE[ta1 & 0x0F]

    @property
    def fmax_mhz(self) -> float | None:
        ta1 = self.interface_bytes.get("TA1", 0x11)
        return FMAX_TABLE[ta1 >> 4]

    @property
    def specific_mode(self) -> bool:
        return "TA2" in self.interface_bytes

    @property
    def class_indicator(self) -> str | None:
        """Voltage classes from the first TA for T=15 (ISO 7816-3 §8.3)."""
        for name, value in self.interface_bytes.items():
            idx = int(name[2:])
            if name.startswith("TA") and idx >= 3:
                td_prev = self.interface_bytes.get(f"TD{idx - 1}")
                if td_prev is not None and (td_prev & 0x0F) == 15:
                    classes = value & 0x3F
                    names = {1: "A (5V)", 2: "B (3V)", 3: "A/B (5V,3V)", 4: "C (1.8V)", 6: "B/C (3V,1.8V)",
                             7: "A/B/C (5V,3V,1.8V)"}
                    text = names.get(classes, f"0x{classes:02X}")
                    if value & 0x80:
                        text += ", clock stop supported"
                    return text
        return None

    @property
    def t1_parameters(self) -> dict[str, int | str] | None:
        """IFSC / BWI / CWI / checksum for T=1.

        Per ISO 7816-3 the protocol parameters follow the first TD that indicates T=1:
        TA(i+1) = IFSC, TB(i+1) = BWI/CWI, TC(i+1) = checksum type (i >= 2).
        """
        for name, value in self.interface_bytes.items():
            if not name.startswith("TD") or (value & 0x0F) != 1:
                continue
            i = int(name[2:]) + 1
            if i < 3:
                continue
            out: dict[str, int | str] = {}
            if f"TA{i}" in self.interface_bytes:
                out["IFSC"] = self.interface_bytes[f"TA{i}"]
            if f"TB{i}" in self.interface_bytes:
                tb = self.interface_bytes[f"TB{i}"]
                out["BWI"] = tb >> 4
                out["CWI"] = tb & 0x0F
            if f"TC{i}" in self.interface_bytes:
                out["checksum"] = "CRC" if self.interface_bytes[f"TC{i}"] & 1 else "LRC"
            if out:
                return out
        return None

    def emv_compliance(self) -> list[str]:
        """Check the ATR against the EMV Book 1 (section 8.3) rules for EMVCo Level 1 terminals.

        Returns a list of violations (empty = compliant).  The 3021 is an EMV L1
        certified reader; this tells you whether the *card* answers the way an EMV
        terminal expects.
        """
        issues: list[str] = []
        ib = self.interface_bytes
        if self.kind != CardKind.ASYNC:
            return ["not an asynchronous ISO 7816-3 card"]
        if self.ts not in (0x3B, 0x3F):
            issues.append(f"TS must be 3B or 3F, got {self.ts:02X}")
        if len(self.historical) > 15:
            issues.append("more than 15 historical bytes")
        ta1 = ib.get("TA1")
        ta2 = ib.get("TA2")
        if ta1 is not None and ta1 not in (0x11, 0x13) and ta2 is None:
            issues.append(f"TA1={ta1:02X} without TA2: terminal must keep default 372/1 (negotiable mode not allowed)")
        if ta2 is not None:
            if ta2 & 0x10:
                issues.append("TA2 bit 5 set (implicit mode parameters) is not allowed")
            if (ta2 & 0x0F) not in (0, 1):
                issues.append(f"TA2 indicates T={ta2 & 0x0F}; only T=0/T=1 allowed")
        tb1 = ib.get("TB1")
        if tb1 is None:
            issues.append("TB1 absent (EMV requires TB1 = 00 in a cold ATR)")
        elif tb1 != 0x00:
            issues.append(f"TB1={tb1:02X}, must be 00 (no VPP)")
        tc1 = ib.get("TC1")
        if tc1 is not None and tc1 not in (0x00, 0xFF):
            issues.append(f"TC1={tc1:02X}, must be 00 or FF")
        td1 = ib.get("TD1")
        if td1 is not None and (td1 & 0x0F) not in (0, 1):
            issues.append(f"TD1 indicates T={td1 & 0x0F}; only T=0/T=1 allowed")
        if "TB2" in ib:
            issues.append("TB2 present (not allowed)")
        tc2 = ib.get("TC2")
        if tc2 is not None and tc2 != 0x0A:
            issues.append(f"TC2={tc2:02X}, must be 0A (WI=10) when present")
        td2 = ib.get("TD2")
        if td2 is not None:
            proto = td2 & 0x0F
            if td1 is not None and (td1 & 0x0F) == 1 and proto != 1:
                issues.append("TD2 must indicate T=1 when TD1 indicates T=1")
            if td1 is not None and (td1 & 0x0F) == 0 and proto not in (1, 14, 15):
                issues.append("TD2 after T=0 must indicate T=1, T=14 or T=15")
        if td1 is not None and (td1 & 0x0F) == 1:
            ta3 = ib.get("TA3")
            if ta3 is not None and not 0x10 <= ta3 <= 0xFE:
                issues.append(f"TA3 (IFSC)={ta3:02X}, must be 10..FE")
            tb3 = ib.get("TB3")
            if tb3 is None:
                issues.append("TB3 absent although T=1 is indicated")
            else:
                bwi, cwi = tb3 >> 4, tb3 & 0x0F
                if bwi > 4:
                    issues.append(f"BWI={bwi}, must be <= 4")
                if cwi > 5:
                    issues.append(f"CWI={cwi}, must be <= 5")
                n = tc1 if tc1 is not None else 0
                if n != 0xFF and (1 << cwi) < n + 1:
                    issues.append("2^CWI must be >= N+1 (TC1)")
            tc3 = ib.get("TC3")
            if tc3 is not None and tc3 != 0x00:
                issues.append(f"TC3={tc3:02X}, must be 00 (LRC)")
        if self.tck is not None and not self.tck_valid:
            issues.append("TCK checksum invalid")
        if self.tck is None and any(p != 0 for p in self.protocols):
            issues.append("TCK missing")
        return issues

    def describe(self) -> list[str]:
        lines = [f"ATR: {self.raw.hex(' ').upper()}"]
        lines.append(f"Card kind: {self.kind.value}")
        if self.kind == CardKind.ASYNC or self.interface_bytes:
            lines.append("Convention: " + ("direct (TS=3B)" if self.direct_convention else "inverse (TS=3F)"))
            lines.append("Protocols: " + (", ".join(f"T={p}" for p in self.protocols) or "T=0 (default)"))
            if "TA1" in self.interface_bytes:
                lines.append(f"TA1=0x{self.interface_bytes['TA1']:02X}: Fi={self.fi} Di={self.di} fmax={self.fmax_mhz} MHz")
            if self.specific_mode:
                lines.append(f"TA2=0x{self.interface_bytes['TA2']:02X}: specific mode")
            ci = self.class_indicator
            if ci:
                lines.append(f"Voltage class: {ci}")
            t1 = self.t1_parameters
            if t1:
                lines.append("T=1 parameters: " + ", ".join(f"{k}={v}" for k, v in t1.items()))
            for name, value in self.interface_bytes.items():
                lines.append(f"  {name} = 0x{value:02X}")
        if self.historical:
            lines.append(f"Historical bytes: {self.historical.hex(' ').upper()}")
            printable = "".join(chr(b) if 32 <= b < 127 else "." for b in self.historical)
            lines.append(f"  as text: {printable}")
        if self.tck is not None:
            lines.append(f"TCK: 0x{self.tck:02X} ({'valid' if self.tck_valid else 'INVALID'})")
        for w in self.warnings:
            lines.append(f"Warning: {w}")
        return lines


def parse_atr(raw: bytes) -> ATR:
    raw = bytes(raw)
    atr = ATR(raw=raw)
    if not raw:
        atr.kind = CardKind.UNKNOWN
        atr.warnings.append("empty ATR")
        return atr

    # Memory-card pseudo ATRs: "3B 04 <hdr>" or bare 4-byte header.
    for hdr, kind in SYNC_HEADERS.items():
        if raw == hdr or raw == b"\x3b\x04" + hdr or raw.startswith(b"\x3b\x04" + hdr):
            atr.kind = kind
            atr.ts = raw[0]
            atr.historical = raw[2:] if raw[:2] == b"\x3b\x04" else raw
            return atr

    if raw[0] not in (0x3B, 0x3F):
        atr.kind = CardKind.UNKNOWN_SYNC
        atr.warnings.append(f"TS byte 0x{raw[0]:02X} is neither 3B nor 3F: not an ISO 7816-3 ATR")
        return atr

    atr.ts = raw[0]
    if len(raw) < 2:
        atr.warnings.append("ATR truncated after TS")
        return atr
    atr.t0 = raw[1]
    k = atr.t0 & 0x0F
    y = atr.t0 >> 4
    pos = 2
    i = 1
    protocols: list[int] = []
    while True:
        for bit, name in ((0x1, "TA"), (0x2, "TB"), (0x4, "TC"), (0x8, "TD")):
            if y & bit:
                if pos >= len(raw):
                    atr.warnings.append(f"ATR truncated before {name}{i}")
                    atr.kind = CardKind.ASYNC
                    return atr
                atr.interface_bytes[f"{name}{i}"] = raw[pos]
                pos += 1
        td = atr.interface_bytes.get(f"TD{i}")
        if td is None:
            break
        proto = td & 0x0F
        if proto not in protocols:
            protocols.append(proto)
        y = td >> 4
        i += 1
    atr.protocols = [p for p in protocols if p != 15] or ([0] if not protocols else [])
    # T=0 is implied when TD1 is absent.
    if "TD1" not in atr.interface_bytes:
        atr.protocols = [0]
    atr.historical = raw[pos : pos + k]
    if len(atr.historical) < k:
        atr.warnings.append(f"ATR declares {k} historical bytes but only {len(atr.historical)} present")
    pos += len(atr.historical)
    tck_expected = any(p != 0 for p in protocols)
    if pos < len(raw):
        atr.tck = raw[pos]
        xor = 0
        for b in raw[1 : pos + 1]:
            xor ^= b
        atr.tck_valid = xor == 0
        if not tck_expected:
            atr.warnings.append("TCK present although only T=0 is indicated")
        if pos + 1 < len(raw):
            atr.warnings.append(f"{len(raw) - pos - 1} trailing byte(s) after TCK")
    elif tck_expected:
        atr.warnings.append("TCK missing although a protocol other than T=0 is indicated")
    atr.kind = CardKind.ASYNC
    if k and atr.historical and atr.historical in SYNC_HEADERS:
        atr.kind = SYNC_HEADERS[atr.historical]
    return atr
