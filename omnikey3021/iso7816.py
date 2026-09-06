"""ISO/IEC 7816-4 command layer for asynchronous (CPU) cards, T=0 or T=1.

The OMNIKEY 3021 forwards standard APDUs untouched, so this module is plain
ISO 7816-4: file selection, transparent/record file access, PIN handling,
challenge/response and GET/PUT DATA.  Every method returns a ``ResponseAPDU``
(or decoded data) and raises ``CardError`` on a non-9000 status unless the
status is a warning the caller explicitly allows.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .apdu import CommandAPDU, ResponseAPDU, transmit_apdu
from .channel import CardChannel
from .tlv import TLV, decode

INS_ERASE_BINARY = 0x0E
INS_VERIFY = 0x20
INS_MANAGE_CHANNEL = 0x70
INS_EXTERNAL_AUTHENTICATE = 0x82
INS_GET_CHALLENGE = 0x84
INS_INTERNAL_AUTHENTICATE = 0x88
INS_SELECT = 0xA4
INS_READ_BINARY = 0xB0
INS_READ_RECORD = 0xB2
INS_GET_RESPONSE = 0xC0
INS_ENVELOPE = 0xC2
INS_GET_DATA = 0xCA
INS_WRITE_BINARY = 0xD0
INS_WRITE_RECORD = 0xD2
INS_UPDATE_BINARY = 0xD6
INS_PUT_DATA = 0xDA
INS_UPDATE_RECORD = 0xDC
INS_APPEND_RECORD = 0xE2
INS_CHANGE_REFERENCE_DATA = 0x24
INS_RESET_RETRY_COUNTER = 0x2C
INS_DISABLE_VERIFICATION = 0x26
INS_ENABLE_VERIFICATION = 0x28

FILE_DESCRIPTORS = {
    0x38: "DF", 0x01: "transparent EF", 0x02: "linear fixed EF", 0x03: "linear fixed EF (TLV)",
    0x04: "linear variable EF", 0x05: "linear variable EF (TLV)", 0x06: "cyclic EF", 0x07: "cyclic EF (TLV)",
    0x11: "transparent EF (working)", 0x41: "transparent EF (internal)",
}


@dataclass
class FCI:
    """Parsed File Control Information (template 6F / FCP 62 / FMD 64)."""

    raw: bytes
    template: TLV | None = None
    file_size: int | None = None
    total_size: int | None = None
    descriptor: bytes | None = None
    fid: int | None = None
    df_name: bytes | None = None
    sfi: int | None = None
    lifecycle: int | None = None
    proprietary: dict[int, bytes] = field(default_factory=dict)

    @property
    def descriptor_text(self) -> str:
        if not self.descriptor:
            return "unknown"
        b0 = self.descriptor[0]
        name = FILE_DESCRIPTORS.get(b0 & 0x3F, FILE_DESCRIPTORS.get(b0, f"0x{b0:02X}"))
        if len(self.descriptor) >= 3:
            rec = int.from_bytes(self.descriptor[1:3], "big")
            name += f", record size {rec}"
        if len(self.descriptor) >= 4:
            name += f", {self.descriptor[3]} records"
        return name

    @property
    def record_size(self) -> int | None:
        if self.descriptor and len(self.descriptor) >= 3:
            return int.from_bytes(self.descriptor[1:3], "big")
        return None

    @property
    def record_count(self) -> int | None:
        if self.descriptor and len(self.descriptor) >= 4:
            return self.descriptor[3]
        return None

    @classmethod
    def parse(cls, raw: bytes) -> "FCI":
        fci = cls(raw=bytes(raw))
        if not raw:
            return fci
        try:
            items = decode(raw)
        except ValueError:
            return fci
        if not items:
            return fci
        template = items[0]
        fci.template = template
        nodes = template.children if template.children else items
        for node in nodes:
            if node.tag == 0x80:
                fci.file_size = int.from_bytes(node.value, "big")
            elif node.tag == 0x81:
                fci.total_size = int.from_bytes(node.value, "big")
            elif node.tag == 0x82:
                fci.descriptor = node.value
            elif node.tag == 0x83 and len(node.value) == 2:
                fci.fid = int.from_bytes(node.value, "big")
            elif node.tag == 0x84:
                fci.df_name = node.value
            elif node.tag == 0x88 and node.value:
                fci.sfi = node.value[0] >> 3
            elif node.tag == 0x8A and node.value:
                fci.lifecycle = node.value[0]
            else:
                fci.proprietary[node.tag] = node.value
        return fci

    def describe(self) -> list[str]:
        out = [f"FCI: {self.raw.hex(' ').upper()}" if self.raw else "FCI: (none)"]
        if self.fid is not None:
            out.append(f"  FID: {self.fid:04X}")
        if self.df_name is not None:
            out.append(f"  DF name / AID: {self.df_name.hex().upper()}")
        if self.descriptor is not None:
            out.append(f"  Type: {self.descriptor_text}")
        if self.file_size is not None:
            out.append(f"  Size: {self.file_size} bytes")
        if self.total_size is not None:
            out.append(f"  Total size: {self.total_size} bytes")
        if self.sfi is not None:
            out.append(f"  Short file identifier: {self.sfi}")
        if self.lifecycle is not None:
            out.append(f"  Life cycle status: 0x{self.lifecycle:02X}")
        for tag, value in self.proprietary.items():
            out.append(f"  Tag {tag:X}: {value.hex().upper()}")
        return out


class Iso7816Card:
    """Generic ISO 7816-4 card bound to a CardChannel."""

    MAX_SHORT = 255       # bytes per short READ/UPDATE BINARY chunk (Le=00 reads up to 256)
    MAX_EXTENDED = 65535

    def __init__(self, channel: CardChannel, cla: int = 0x00, extended: bool = False):
        self.channel = channel
        self.cla = cla
        self.extended = extended
        self.last_response: ResponseAPDU | None = None

    # -- primitive -----------------------------------------------------------------
    def send(self, ins: int, p1: int = 0, p2: int = 0, data: bytes = b"", le: int | None = None,
             cla: int | None = None, check: bool = True, allow_warnings: bool = False) -> ResponseAPDU:
        cmd = CommandAPDU(self.cla if cla is None else cla, ins, p1, p2, bytes(data), le, self.extended)
        resp = transmit_apdu(self.channel.transmit, cmd)
        self.last_response = resp
        if check:
            resp.check(cmd.to_bytes(), allow_warnings=allow_warnings)
        return resp

    def raw(self, apdu: bytes, check: bool = False) -> ResponseAPDU:
        resp = transmit_apdu(self.channel.transmit, apdu)
        self.last_response = resp
        if check:
            resp.check(bytes(apdu))
        return resp

    # -- SELECT ------------------------------------------------------------------------
    def select(self, p1: int, p2: int, data: bytes = b"", le: int | None = 256) -> FCI:
        resp = self.send(INS_SELECT, p1, p2, data, le, allow_warnings=True)
        return FCI.parse(resp.data)

    def select_mf(self) -> FCI:
        return self.select(0x00, 0x00, b"\x3f\x00")

    def select_fid(self, fid: int, p2: int = 0x00) -> FCI:
        """Select an EF/DF under the current DF by 2-byte identifier (P1=00)."""
        return self.select(0x00, p2, fid.to_bytes(2, "big"))

    def select_df(self, fid: int) -> FCI:
        return self.select(0x01, 0x00, fid.to_bytes(2, "big"))

    def select_ef(self, fid: int) -> FCI:
        return self.select(0x02, 0x00, fid.to_bytes(2, "big"))

    def select_parent(self) -> FCI:
        return self.select(0x03, 0x00, b"")

    def select_aid(self, aid: bytes, first: bool = True, return_fci: bool = True) -> FCI:
        p2 = (0x00 if first else 0x02) | (0x00 if return_fci else 0x0C)
        return self.select(0x04, p2, bytes(aid), 256 if return_fci else None)

    def select_path(self, path: bytes, from_mf: bool = True) -> FCI:
        """Select by path of concatenated FIDs (P1=08 from MF, P1=09 from current DF)."""
        return self.select(0x08 if from_mf else 0x09, 0x00, bytes(path))

    # -- transparent files ------------------------------------------------------------
    def read_binary(self, offset: int = 0, length: int | None = None, sfi: int | None = None) -> bytes:
        """READ BINARY; ``length=None`` reads until the card reports end-of-file."""
        out = bytearray()
        remaining = length
        chunk_max = self.MAX_EXTENDED if self.extended else 256
        while remaining is None or remaining > 0:
            want = chunk_max if remaining is None else min(remaining, chunk_max)
            if sfi is not None:
                if offset > 0xFF:
                    raise ValueError("offset exceeds 255 when addressing by SFI")
                p1, p2 = 0x80 | (sfi & 0x1F), offset & 0xFF
                sfi_used = True
            else:
                if offset > 0x7FFF:
                    raise ValueError("offset exceeds 32767 (use offset data objects / a different EF)")
                p1, p2 = (offset >> 8) & 0x7F, offset & 0xFF
                sfi_used = False
            resp = self.send(INS_READ_BINARY, p1, p2, le=want, check=False)
            if resp.sw == 0x6282 or (resp.sw1 == 0x62 and resp.data):
                out += resp.data
                break
            if resp.sw == 0x6B00 and out:
                break  # offset beyond EOF after a complete read
            if resp.sw1 == 0x6C:
                resp = self.send(INS_READ_BINARY, p1, p2, le=resp.sw2 or 256)
            resp.check()
            out += resp.data
            if not resp.data:
                break
            offset += len(resp.data)
            if remaining is not None:
                remaining -= len(resp.data)
            if remaining is None and len(resp.data) < want:
                break
            if sfi_used:
                sfi = None  # subsequent chunks address the now-current EF
        return bytes(out)

    def update_binary(self, offset: int, data: bytes, sfi: int | None = None) -> None:
        data = bytes(data)
        chunk_max = self.MAX_EXTENDED if self.extended else self.MAX_SHORT
        pos = 0
        while pos < len(data):
            chunk = data[pos : pos + chunk_max]
            if sfi is not None and pos == 0:
                p1, p2 = 0x80 | (sfi & 0x1F), offset & 0xFF
            else:
                p1, p2 = (offset >> 8) & 0x7F, offset & 0xFF
            self.send(INS_UPDATE_BINARY, p1, p2, chunk)
            pos += len(chunk)
            offset += len(chunk)

    def write_binary(self, offset: int, data: bytes) -> None:
        self.send(INS_WRITE_BINARY, (offset >> 8) & 0x7F, offset & 0xFF, bytes(data))

    def erase_binary(self, offset: int, end: int | None = None) -> None:
        data = end.to_bytes(2, "big") if end is not None else b""
        self.send(INS_ERASE_BINARY, (offset >> 8) & 0x7F, offset & 0xFF, data)

    # -- record files -----------------------------------------------------------------------
    def read_record(self, number: int, sfi: int | None = None, le: int = 256) -> bytes:
        p2 = 0x04 | ((sfi & 0x1F) << 3 if sfi is not None else 0)
        return self.send(INS_READ_RECORD, number, p2, le=le, allow_warnings=True).data

    def read_all_records(self, sfi: int | None = None, max_records: int = 254) -> list[bytes]:
        records: list[bytes] = []
        for n in range(1, max_records + 1):
            p2 = 0x04 | ((sfi & 0x1F) << 3 if sfi is not None else 0)
            resp = self.send(INS_READ_RECORD, n, p2, le=256, check=False)
            if resp.sw in (0x6A83, 0x6A82, 0x6982, 0x6985):
                break
            if resp.sw1 == 0x6C:
                resp = self.send(INS_READ_RECORD, n, p2, le=resp.sw2 or 256, check=False)
            if not resp.ok and not resp.warning:
                if records:
                    break
                resp.check()
            records.append(resp.data)
        return records

    def update_record(self, number: int, data: bytes, sfi: int | None = None) -> None:
        p2 = 0x04 | ((sfi & 0x1F) << 3 if sfi is not None else 0)
        self.send(INS_UPDATE_RECORD, number, p2, bytes(data))

    def append_record(self, data: bytes, sfi: int | None = None) -> None:
        p2 = (sfi & 0x1F) << 3 if sfi is not None else 0
        self.send(INS_APPEND_RECORD, 0x00, p2, bytes(data))

    # -- security ------------------------------------------------------------------------------
    def verify(self, pin: bytes | str, reference: int = 0x00, pad_to: int | None = None, pad_byte: int = 0xFF) -> None:
        """VERIFY.  ``reference`` is P2 (e.g. 0x01 = global PIN 1, 0x81 = local PIN 1)."""
        data = pin.encode("ascii") if isinstance(pin, str) else bytes(pin)
        if pad_to and len(data) < pad_to:
            data += bytes([pad_byte]) * (pad_to - len(data))
        self.send(INS_VERIFY, 0x00, reference, data)

    def verify_retries(self, reference: int = 0x00) -> int | None:
        """Query remaining PIN tries (VERIFY with empty data -> 63 Cx)."""
        resp = self.send(INS_VERIFY, 0x00, reference, check=False)
        if resp.sw1 == 0x63 and (resp.sw2 & 0xF0) == 0xC0:
            return resp.sw2 & 0x0F
        if resp.ok:
            return None  # PIN already verified / not required
        if resp.sw == 0x6983:
            return 0
        resp.check()
        return None

    def change_reference_data(self, old: bytes | str, new: bytes | str, reference: int = 0x00) -> None:
        o = old.encode("ascii") if isinstance(old, str) else bytes(old)
        n = new.encode("ascii") if isinstance(new, str) else bytes(new)
        self.send(INS_CHANGE_REFERENCE_DATA, 0x00, reference, o + n)

    def reset_retry_counter(self, puk: bytes | str, new_pin: bytes | str | None = None, reference: int = 0x00) -> None:
        p = puk.encode("ascii") if isinstance(puk, str) else bytes(puk)
        if new_pin is None:
            self.send(INS_RESET_RETRY_COUNTER, 0x01, reference, p)
        else:
            n = new_pin.encode("ascii") if isinstance(new_pin, str) else bytes(new_pin)
            self.send(INS_RESET_RETRY_COUNTER, 0x00, reference, p + n)

    def get_challenge(self, length: int = 8) -> bytes:
        return self.send(INS_GET_CHALLENGE, 0x00, 0x00, le=length).data

    def internal_authenticate(self, data: bytes, algorithm: int = 0x00, reference: int = 0x00, le: int = 256) -> bytes:
        return self.send(INS_INTERNAL_AUTHENTICATE, algorithm, reference, bytes(data), le).data

    def external_authenticate(self, data: bytes, algorithm: int = 0x00, reference: int = 0x00) -> None:
        self.send(INS_EXTERNAL_AUTHENTICATE, algorithm, reference, bytes(data))

    # -- data objects -------------------------------------------------------------------------
    def get_data(self, tag: int, le: int = 256) -> bytes:
        return self.send(INS_GET_DATA, (tag >> 8) & 0xFF, tag & 0xFF, le=le).data

    def put_data(self, tag: int, data: bytes) -> None:
        self.send(INS_PUT_DATA, (tag >> 8) & 0xFF, tag & 0xFF, bytes(data))

    def get_response(self, le: int = 256) -> bytes:
        return self.send(INS_GET_RESPONSE, 0x00, 0x00, le=le).data

    def envelope(self, apdu: bytes, le: int = 256) -> ResponseAPDU:
        """Wrap a (long) command in ENVELOPE - the T=0 substitute for extended APDUs (PLT-03099 §5.3.3)."""
        return self.send(INS_ENVELOPE, 0x00, 0x00, bytes(apdu), le)

    def manage_channel_open(self) -> int:
        resp = self.send(INS_MANAGE_CHANNEL, 0x00, 0x00, le=1)
        return resp.data[0] if resp.data else 0

    def manage_channel_close(self, channel: int) -> None:
        self.send(INS_MANAGE_CHANNEL, 0x80, channel)
