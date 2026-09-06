"""BER-TLV (ISO 8825 / X.690) encoding and decoding.

Used for the OMNIKEY vendor command payloads (which are DER-TLV coded) and for
ISO 7816-4 FCI/FCP templates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class TLV:
    tag: int
    value: bytes = b""
    children: list["TLV"] = field(default_factory=list)

    @property
    def constructed(self) -> bool:
        first = self.tag >> (8 * (max(_tag_len(self.tag), 1) - 1))
        return bool(first & 0x20)

    def find(self, tag: int) -> "TLV | None":
        for child in self.children:
            if child.tag == tag:
                return child
        return None

    def find_all(self, tag: int) -> list["TLV"]:
        return [c for c in self.children if c.tag == tag]

    def find_deep(self, tag: int) -> "TLV | None":
        for child in self.children:
            if child.tag == tag:
                return child
            found = child.find_deep(tag)
            if found is not None:
                return found
        return None

    def encode(self) -> bytes:
        payload = b"".join(c.encode() for c in self.children) if self.children else self.value
        return encode_tag(self.tag) + encode_length(len(payload)) + payload

    def pretty(self, indent: int = 0) -> str:
        pad = "  " * indent
        if self.children:
            lines = [f"{pad}{encode_tag(self.tag).hex().upper()} ({len(self.encode()) - len(encode_tag(self.tag)) - len(encode_length(len(self.encode())))} bytes)"]
            for c in self.children:
                lines.append(c.pretty(indent + 1))
            return "\n".join(lines)
        return f"{pad}{encode_tag(self.tag).hex().upper()} {len(self.value):02X} {self.value.hex().upper()}"


def _tag_len(tag: int) -> int:
    n = 0
    while tag:
        n += 1
        tag >>= 8
    return n


def encode_tag(tag: int) -> bytes:
    return tag.to_bytes(max(_tag_len(tag), 1), "big")


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    if length <= 0xFFFF:
        return bytes([0x82]) + length.to_bytes(2, "big")
    if length <= 0xFFFFFF:
        return bytes([0x83]) + length.to_bytes(3, "big")
    return bytes([0x84]) + length.to_bytes(4, "big")


def tlv(tag: int, value: bytes | int | None = b"", *children: TLV) -> TLV:
    """Shorthand constructor.  ``value`` may be bytes or a single byte int."""
    if isinstance(value, int):
        value = bytes([value])
    return TLV(tag, value or b"", list(children))


def encode(tag: int, value: bytes | int = b"", *children: TLV) -> bytes:
    return tlv(tag, value, *children).encode()


def _read_tag(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise ValueError("truncated TLV: missing tag")
    first = data[pos]
    tag = first
    pos += 1
    if (first & 0x1F) == 0x1F:
        while True:
            if pos >= len(data):
                raise ValueError("truncated TLV: multi-byte tag")
            b = data[pos]
            tag = (tag << 8) | b
            pos += 1
            if not (b & 0x80):
                break
    return tag, pos


def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise ValueError("truncated TLV: missing length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7F
    if n == 0 or n > 4:
        raise ValueError(f"unsupported TLV length encoding 0x{first:02X}")
    if pos + n > len(data):
        raise ValueError("truncated TLV: length bytes")
    return int.from_bytes(data[pos : pos + n], "big"), pos + n


def iter_decode(data: bytes, recurse: bool = True) -> Iterator[TLV]:
    pos = 0
    while pos < len(data):
        # Skip padding bytes commonly found in EF contents.
        if data[pos] in (0x00, 0xFF):
            pos += 1
            continue
        tag, pos = _read_tag(data, pos)
        length, pos = _read_length(data, pos)
        if pos + length > len(data):
            raise ValueError(f"truncated TLV: tag {tag:X} declares {length} bytes, {len(data) - pos} remain")
        value = data[pos : pos + length]
        pos += length
        node = TLV(tag, value)
        if recurse and node.constructed and value:
            try:
                node.children = list(iter_decode(value, True))
            except ValueError:
                node.children = []
        yield node


def decode(data: bytes, recurse: bool = True) -> list[TLV]:
    return list(iter_decode(bytes(data), recurse))


def decode_one(data: bytes) -> TLV:
    items = decode(data)
    if len(items) != 1:
        raise ValueError(f"expected exactly one TLV object, found {len(items)}")
    return items[0]
