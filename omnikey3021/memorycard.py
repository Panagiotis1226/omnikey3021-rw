"""Synchronous (memory) card support through the OMNIKEY PC/SC command set.

Implements PLT-03099 chapter 8.1 - the reader emulates T=0 and accepts these
CLA=FF pseudo APDUs for SLE 4418/4428 (3-wire), SLE 4432/4442 (2-wire) and
I2C EEPROM cards:

    FF B0 <addr hi> <addr lo> Le            READ BINARY
    FF D6 <addr hi> <addr lo> Lc data       UPDATE BINARY
    FF 20 00 00 Lc PIN                      VERIFY (PSC)
    FF 21 00 00 Lc old+new                  MODIFY (change PSC)
    FF 3A <addr hi> <addr lo> Le            READ PROTECTION MEMORY
    FF 30 00 03 Lc 01 00 00 hi lo data      COMPARE AND PROTECT
    FF 30 00 04 08 01 type page nAddr size4 I2C INIT
    FF 30 00 05 09 01 addr4 len4            I2C READ
    FF 30 00 06 Lc 01 addr4 data            I2C WRITE

Chapter 8.2 raw bus commands (2WBP/3WBP) are used for the few things the
PC/SC set does not expose (reading the SLE 4442 security memory / error counter).
"""

from __future__ import annotations

from dataclasses import dataclass

from . import vendor
from .apdu import CommandAPDU, ResponseAPDU, transmit_apdu
from .atr import CardKind, parse_atr
from .channel import CardChannel
from .errors import CardError, UnsupportedCardError

CLA_SYNC = 0xFF
INS_READ_BINARY = 0xB0
INS_UPDATE_BINARY = 0xD6
INS_VERIFY = 0x20
INS_MODIFY = 0x21
INS_READ_PROTECTION = 0x3A
INS_PROPRIETARY = 0x30
P2_COMPARE_AND_PROTECT = 0x03
P2_I2C_INIT = 0x04
P2_I2C_READ = 0x05
P2_I2C_WRITE = 0x06


@dataclass(frozen=True)
class I2CType:
    code: int
    name: str
    page_size: int
    address_bytes: int
    memory_size: int


# Table "Type - definitions" from PLT-03099 section 8.1.7.
I2C_TYPES: dict[int, I2CType] = {
    t.code: t
    for t in [
        I2CType(0x01, "ST14C02C", 8, 1, 256),
        I2CType(0x02, "ST14C04C", 8, 1, 512),
        I2CType(0x03, "ST14E32", 32, 2, 4096),
        I2CType(0x04, "M14C04", 16, 1, 512),
        I2CType(0x05, "M14C16", 16, 1, 2048),
        I2CType(0x06, "M14C32", 32, 2, 4096),
        I2CType(0x07, "M14C64", 32, 2, 8192),
        I2CType(0x08, "M14128", 64, 2, 16384),
        I2CType(0x09, "M14256", 64, 2, 32768),
        I2CType(0x0A, "GFM2K", 8, 1, 256),
        I2CType(0x0B, "GFM4K", 16, 1, 512),
        I2CType(0x0C, "GFM32K", 32, 2, 4096),
        I2CType(0x0D, "AT24C01A", 8, 1, 128),
        I2CType(0x0E, "AT24C02", 8, 1, 256),
        I2CType(0x0F, "AT24C04", 16, 1, 512),
        I2CType(0x10, "AT24C08", 16, 1, 1024),
        I2CType(0x11, "AT24C16", 16, 1, 2048),
        I2CType(0x12, "AT24C164", 16, 1, 2048),
        I2CType(0x13, "AT24C32", 32, 2, 4096),
        I2CType(0x14, "AT24C64", 32, 2, 8192),
        I2CType(0x15, "AT24C128", 64, 2, 16384),
        I2CType(0x16, "AT24C256", 64, 2, 32768),
        I2CType(0x17, "AT24CS128", 64, 2, 16384),
        I2CType(0x18, "AT24CS256", 64, 2, 32768),
        I2CType(0x19, "AT24C512", 128, 2, 65536),
        I2CType(0x1A, "AT24C1024", 256, 2, 131072),
        I2CType(0x1B, "X24026", 4, 1, 256),
    ]
}
I2C_TYPES_BY_NAME = {t.name.lower(): t for t in I2C_TYPES.values()}


class MemoryCard:
    """Base class: READ/UPDATE BINARY on the synchronous card via CLA FF."""

    size: int = 256
    name: str = "memory card"
    kind: CardKind = CardKind.UNKNOWN_SYNC

    def __init__(self, channel: CardChannel):
        self.channel = channel
        self.last_response: ResponseAPDU | None = None

    # -- primitive -----------------------------------------------------------------
    def _send(self, ins: int, p1: int, p2: int, data: bytes = b"", le: int | None = None,
              check: bool = True, allow_warnings: bool = False) -> ResponseAPDU:
        cmd = CommandAPDU(CLA_SYNC, ins, p1, p2, bytes(data), le)
        resp = transmit_apdu(self.channel.transmit, cmd, auto_get_response=False)
        self.last_response = resp
        if check:
            resp.check(cmd.to_bytes(), allow_warnings=allow_warnings)
        return resp

    # -- memory access ---------------------------------------------------------------
    def read(self, address: int = 0, length: int | None = None) -> bytes:
        """Read ``length`` bytes (default: to end of memory) starting at ``address``."""
        if length is None:
            length = self.size - address
        if address < 0 or address + length > self.size:
            raise ValueError(f"address range {address}..{address + length} exceeds {self.size} bytes")
        out = bytearray()
        while length > 0:
            chunk = min(length, 256)
            resp = self._send(INS_READ_BINARY, address >> 8, address & 0xFF, le=chunk, allow_warnings=True)
            if resp.sw == 0x6282 and not resp.data:
                break
            out += resp.data
            if len(resp.data) == 0:
                break
            address += len(resp.data)
            length -= len(resp.data)
        return bytes(out)

    def write(self, address: int, data: bytes, verify: bool = False) -> None:
        """Write ``data`` at ``address`` (PSC must be verified first on SLE 4428/4442)."""
        data = bytes(data)
        if address < 0 or address + len(data) > self.size:
            raise ValueError(f"write range {address}..{address + len(data)} exceeds {self.size} bytes")
        pos = 0
        while pos < len(data):
            chunk = data[pos : pos + 255]
            addr = address + pos
            self._send(INS_UPDATE_BINARY, addr >> 8, addr & 0xFF, chunk)
            pos += len(chunk)
        if verify:
            back = self.read(address, len(data))
            if back != data:
                raise CardError(0x65, 0x81, "read-back mismatch after write")

    def dump(self) -> bytes:
        return self.read(0, self.size)

    def info(self) -> dict[str, str]:
        return {"type": self.name, "size": f"{self.size} bytes", "atr": self.channel.atr.hex(" ").upper()}


class ProtectableMemoryCard(MemoryCard):
    """Cards with per-byte protection bits (SLE 4418/28/32/42)."""

    psc_length: int = 3
    max_tries: int = 3

    def read_protection_bits(self, address: int, length: int) -> list[bool]:
        """READ PROTECTION MEMORY: one byte per address, bit 0 = protected."""
        if length < 1 or length > 256:
            raise ValueError("length must be 1..256")
        resp = self._send(INS_READ_PROTECTION, address >> 8, address & 0xFF, le=length, allow_warnings=True)
        return [bool(b & 0x01) for b in resp.data]

    def protect(self, address: int, data: bytes) -> None:
        """COMPARE AND PROTECT: set the protection bit for each byte whose content equals ``data``.

        Irreversible.  On SLE 4432/4442 only addresses 0..31 have protection bits.
        """
        data = bytes(data)
        if not data or len(data) > 250:
            raise ValueError("compare 1..250 bytes at a time")
        payload = bytes([0x01, 0x00, 0x00, (address >> 8) & 0xFF, address & 0xFF]) + data
        resp = self._send(INS_PROPRIETARY, 0x00, P2_COMPARE_AND_PROTECT, payload, check=False)
        if not resp.ok:
            where = ""
            if len(resp.data) >= 2:
                where = f" at address {int.from_bytes(resp.data[:2], 'big')}"
            raise CardError(resp.sw1, resp.sw2, resp.description + where)

    def verify_psc(self, psc: bytes) -> None:
        """Present the programmable security code (PIN).  Raises CardError 63Cx with tries left."""
        psc = bytes(psc)
        if len(psc) != self.psc_length:
            raise ValueError(f"{self.name} PSC is {self.psc_length} bytes")
        self._send(INS_VERIFY, 0x00, 0x00, psc)

    def change_psc(self, old: bytes, new: bytes) -> None:
        old, new = bytes(old), bytes(new)
        if len(old) != self.psc_length or len(new) != self.psc_length:
            raise ValueError(f"{self.name} PSC is {self.psc_length} bytes")
        self._send(INS_MODIFY, 0x00, 0x00, old + new)

    def tries_remaining(self) -> int | None:
        """Best effort: number of PSC attempts left (via the raw bus protocol)."""
        return None


class SLE4442Card(ProtectableMemoryCard):
    """SLE 4432 / SLE 4442 / SLE 5542 - 256 byte 2-wire card.

    * bytes 0..31   manufacturer / issuer area, individually protectable (irreversible)
    * bytes 32..255 user area, writable after PSC verification (SLE 4442) or always (SLE 4432)
    * 3 byte PSC, error counter with 3 attempts (SLE 4442)
    """

    size = 256
    name = "SLE4432/SLE4442"
    kind = CardKind.SLE4442
    psc_length = 3
    max_tries = 3
    PROTECTABLE = 32
    DEFAULT_PSC = bytes.fromhex("FFFFFF")

    def read_security_memory(self) -> bytes:
        """Raw 2WBP READ SECURITY MEMORY (4 bytes: error counter + PSC, PSC readable only after verify)."""
        out = bytearray()
        for addr in range(4):
            data = vendor.sync_2wbp(self.channel, vendor.W2_READ_SECURITY, addr, 0x00)
            out += data[:1] if data else b"\x00"
        return bytes(out)

    def tries_remaining(self) -> int | None:
        try:
            ec = self.read_security_memory()[0]
        except Exception:
            return None
        return bin(ec & 0x07).count("1")

    def read_protection_bits(self, address: int = 0, length: int = 32) -> list[bool]:
        if address + length > self.PROTECTABLE:
            raise ValueError("SLE 4432/4442 protection bits exist for addresses 0..31 only")
        return super().read_protection_bits(address, length)

    def info(self) -> dict[str, str]:
        d = super().info()
        d["psc"] = "3 bytes, 3 attempts"
        d["protected_area"] = "bytes 0..31 (32 protection bits)"
        tries = self.tries_remaining()
        if tries is not None:
            d["psc_tries_remaining"] = str(tries)
        return d


class SLE4428Card(ProtectableMemoryCard):
    """SLE 4418 / SLE 4428 / SLE 5528 - 1024 byte 3-wire card, every byte has a protect bit.

    SLE 4428 has a 2 byte PSC with 8 attempts (error counter at address 1021,
    PSC at 1022..1023).  SLE 4418 has no PSC.
    """

    size = 1024
    name = "SLE4418/SLE4428"
    kind = CardKind.SLE4428
    psc_length = 2
    max_tries = 8
    ADDR_ERROR_COUNTER = 0x3FD
    ADDR_PSC = 0x3FE
    DEFAULT_PSC = bytes.fromhex("FFFF")

    def read_error_counter(self) -> int:
        """Raw 3WBP 9-bit read of address 0x3FD; each cleared bit is a failed attempt."""
        control = vendor.W3_READ_8BIT | ((self.ADDR_ERROR_COUNTER >> 8) << 6)
        data = vendor.sync_3wbp(self.channel, control, self.ADDR_ERROR_COUNTER & 0xFF)
        return data[0] if data else 0

    def tries_remaining(self) -> int | None:
        try:
            return bin(self.read_error_counter() & 0xFF).count("1")
        except Exception:
            return None

    def read_with_protect_bits(self, address: int, length: int) -> list[tuple[int, bool]]:
        """Raw 3WBP 9-bit reads: returns (byte, protected) tuples."""
        out = []
        for addr in range(address, address + length):
            control = vendor.W3_READ_9BIT | ((addr >> 8) << 6)
            data = vendor.sync_3wbp(self.channel, control, addr & 0xFF)
            if len(data) >= 2:
                out.append((data[0], bool(data[1] & 0x80)))
            elif data:
                out.append((data[0], False))
        return out

    def info(self) -> dict[str, str]:
        d = super().info()
        d["psc"] = "2 bytes, 8 attempts (SLE 4428 only)"
        d["protected_area"] = "every byte has its own protect bit"
        tries = self.tries_remaining()
        if tries is not None:
            d["psc_tries_remaining"] = str(tries)
        return d


class I2CCard(MemoryCard):
    """I2C serial EEPROM card (AT24Cxx, M14Cxx, ST14Cxx, GFMxx, X24026 ...)."""

    name = "I2C EEPROM"
    kind = CardKind.I2C
    MAX_WRITE = 250

    def __init__(self, channel: CardChannel, card_type: I2CType | int | str | None = None,
                 page_size: int | None = None, address_bytes: int | None = None, memory_size: int | None = None):
        super().__init__(channel)
        self.card_type: I2CType | None = None
        if isinstance(card_type, int):
            self.card_type = I2C_TYPES[card_type]
        elif isinstance(card_type, str):
            key = card_type.lower()
            if key not in I2C_TYPES_BY_NAME:
                raise ValueError(f"unknown I2C type {card_type!r}; known: {', '.join(t.name for t in I2C_TYPES.values())}")
            self.card_type = I2C_TYPES_BY_NAME[key]
        elif isinstance(card_type, I2CType):
            self.card_type = card_type
        if self.card_type is None:
            if None in (page_size, address_bytes, memory_size):
                raise ValueError("either a predefined card_type or page_size, address_bytes and memory_size are required")
            self.card_type = I2CType(0x00, "custom", page_size, address_bytes, memory_size)
        self.size = self.card_type.memory_size
        self.name = f"I2C EEPROM ({self.card_type.name})"
        self._initialised = False

    def init(self) -> None:
        """I2C INIT: tell the reader page size, number of address bytes and memory size."""
        t = self.card_type
        assert t is not None
        payload = bytes([0x01, t.code, t.page_size & 0xFF, t.address_bytes]) + t.memory_size.to_bytes(4, "big")
        self._send(INS_PROPRIETARY, 0x00, P2_I2C_INIT, payload)
        self._initialised = True

    def _ensure_init(self) -> None:
        if not self._initialised:
            self.init()

    def read(self, address: int = 0, length: int | None = None) -> bytes:
        self._ensure_init()
        if length is None:
            length = self.size - address
        if address < 0 or address + length > self.size:
            raise ValueError(f"address range exceeds {self.size} bytes")
        out = bytearray()
        while length > 0:
            chunk = min(length, self.MAX_WRITE)
            payload = bytes([0x01]) + address.to_bytes(4, "big") + chunk.to_bytes(4, "big")
            resp = self._send(INS_PROPRIETARY, 0x00, P2_I2C_READ, payload, le=chunk, allow_warnings=True)
            out += resp.data
            if not resp.data:
                break
            address += len(resp.data)
            length -= len(resp.data)
        return bytes(out)

    def write(self, address: int, data: bytes, verify: bool = False) -> None:
        self._ensure_init()
        data = bytes(data)
        if address < 0 or address + len(data) > self.size:
            raise ValueError(f"write range exceeds {self.size} bytes")
        pos = 0
        while pos < len(data):
            chunk = data[pos : pos + self.MAX_WRITE]
            payload = bytes([0x01]) + (address + pos).to_bytes(4, "big") + chunk
            self._send(INS_PROPRIETARY, 0x00, P2_I2C_WRITE, payload)
            pos += len(chunk)
        if verify and self.read(address, len(data)) != data:
            raise CardError(0x65, 0x81, "read-back mismatch after write")

    def info(self) -> dict[str, str]:
        d = super().info()
        t = self.card_type
        assert t is not None
        d["page_size"] = str(t.page_size)
        d["address_bytes"] = str(t.address_bytes)
        return d


def detect_memory_card(channel: CardChannel) -> CardKind:
    return parse_atr(channel.atr).kind


def open_memory_card(channel: CardChannel, kind: CardKind | str | None = None, **i2c_kwargs) -> MemoryCard:
    """Return the right MemoryCard subclass for the inserted card (or the forced ``kind``)."""
    if kind is None:
        kind = detect_memory_card(channel)
    elif isinstance(kind, str) and not isinstance(kind, CardKind):
        key = kind.lower().replace(" ", "")
        mapping = {"sle4442": CardKind.SLE4442, "sle4432": CardKind.SLE4442, "2wbp": CardKind.SLE4442,
                   "sle4428": CardKind.SLE4428, "sle4418": CardKind.SLE4428, "3wbp": CardKind.SLE4428,
                   "i2c": CardKind.I2C}
        if key not in mapping:
            raise ValueError(f"unknown memory card kind {kind!r}")
        kind = mapping[key]
    if kind == CardKind.SLE4442:
        return SLE4442Card(channel)
    if kind == CardKind.SLE4428:
        return SLE4428Card(channel)
    if kind == CardKind.I2C:
        return I2CCard(channel, **i2c_kwargs)
    raise UnsupportedCardError(
        f"card kind {kind.value if isinstance(kind, CardKind) else kind} is not a supported memory card; "
        "force one with kind='sle4442' | 'sle4428' | 'i2c'"
    )
