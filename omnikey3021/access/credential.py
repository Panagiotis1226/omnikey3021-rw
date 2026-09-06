"""Signed credential block stored on the card.

Layout (64 bytes, big endian)::

    off len
     0   4  magic  "OK3A"
     4   1  version (1)
     5   2  site code
     7   4  card id
    11   4  issued   (unix seconds)
    15   4  expires  (unix seconds, 0 = never)
    19   1  access level
    20   1  flags
    21  11  reserved (zero)
    32  32  HMAC-SHA256(site_key, header[0:32] || binding)

``binding`` ties the block to the physical card (e.g. the write-protected
manufacturer area of an SLE 4442, or the chip serial of a CPU card) so a
block copied to another card fails verification.  Memory cards can still be
cloned bit-for-bit by an attacker who can also forge the manufacturer area;
for high-security doors use CPU cards with challenge/response (see
``AccessController.iso_challenge``).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import struct
import time
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"OK3A"
VERSION = 1
BLOCK_SIZE = 64
HEADER_SIZE = 32
_HEADER = ">4sBHIIIBB11s"

FLAG_ACTIVE = 0x01
FLAG_TEMPORARY = 0x02
FLAG_ADMIN = 0x80


@dataclass
class Credential:
    site_code: int
    card_id: int
    issued: int
    expires: int = 0
    access_level: int = 1
    flags: int = FLAG_ACTIVE

    def header(self) -> bytes:
        return struct.pack(_HEADER, MAGIC, VERSION, self.site_code, self.card_id, self.issued, self.expires,
                           self.access_level, self.flags, b"\x00" * 11)

    @property
    def expired(self) -> bool:
        return self.expires != 0 and time.time() > self.expires

    def describe(self) -> dict[str, str]:
        fmt = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else "never"
        return {
            "site_code": str(self.site_code),
            "card_id": str(self.card_id),
            "issued": fmt(self.issued),
            "expires": fmt(self.expires),
            "access_level": str(self.access_level),
            "flags": f"0x{self.flags:02X}" + (" admin" if self.flags & FLAG_ADMIN else "")
            + (" temporary" if self.flags & FLAG_TEMPORARY else "") + ("" if self.flags & FLAG_ACTIVE else " INACTIVE"),
        }


class CredentialBlock:
    """Pack / unpack / authenticate credential blocks."""

    @staticmethod
    def mac(key: bytes, header: bytes, binding: bytes) -> bytes:
        return hmac.new(key, header + binding, hashlib.sha256).digest()

    @classmethod
    def pack(cls, cred: Credential, key: bytes, binding: bytes) -> bytes:
        header = cred.header()
        return header + cls.mac(key, header, binding)

    @staticmethod
    def parse(block: bytes) -> Credential:
        if len(block) < BLOCK_SIZE:
            raise ValueError(f"credential block is {len(block)} bytes, expected {BLOCK_SIZE}")
        magic, version, site, card_id, issued, expires, level, flags, _ = struct.unpack(_HEADER, block[:HEADER_SIZE])
        if magic != MAGIC:
            raise ValueError("no credential on card (magic mismatch)")
        if version != VERSION:
            raise ValueError(f"unsupported credential version {version}")
        return Credential(site, card_id, issued, expires, level, flags)

    @classmethod
    def verify(cls, block: bytes, key: bytes, binding: bytes) -> bool:
        if len(block) < BLOCK_SIZE:
            return False
        expected = cls.mac(key, block[:HEADER_SIZE], binding)
        return hmac.compare_digest(expected, block[HEADER_SIZE:BLOCK_SIZE])

    @staticmethod
    def is_blank(block: bytes) -> bool:
        return not block or all(b in (0x00, 0xFF) for b in block[:HEADER_SIZE])


def derive_card_key(site_key: bytes, card_id: int, purpose: bytes = b"iso-auth") -> bytes:
    """Per-card key for CPU-card challenge/response (HMAC based derivation)."""
    return hmac.new(site_key, purpose + card_id.to_bytes(4, "big"), hashlib.sha256).digest()[:16]


def load_or_create_key(path: str | os.PathLike, create: bool = True) -> bytes:
    """Load a 32-byte hex site key from ``path``; create it (mode 0600) when missing."""
    p = Path(path)
    if p.exists():
        text = p.read_text().strip()
        key = bytes.fromhex(text)
        if len(key) < 16:
            raise ValueError("site key must be at least 16 bytes")
        return key
    if not create:
        raise FileNotFoundError(f"site key file {p} not found; run `omnikey3021 access init`")
    key = secrets.token_bytes(32)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(key.hex() + "\n")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return key
