"""In-memory simulation of an OMNIKEY 3021 with either a memory card or an ISO 7816 card.

The simulator implements the reader behaviour documented in PLT-03099 (vendor
command tree, synchronous PC/SC command set with its status words, CCID escape
via SCardControl, feature request) so every layer above the transport can be
exercised - and the CLI used - without hardware (``--simulate``).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from . import pcsc_constants as C
from . import vendor as V
from .apdu import CommandAPDU
from .errors import NoCardError
from .tlv import TLV, decode, tlv

SW_OK = b"\x90\x00"


def sw(code: int) -> bytes:
    return code.to_bytes(2, "big")


# ---------------------------------------------------------------------------
# Reader firmware emulation (vendor command tree, user EEPROM, slot config)
# ---------------------------------------------------------------------------
class SimulatedFirmware:
    def __init__(self):
        self.capabilities: dict[int, bytes] = {
            0x80: b"\x01",
            0x81: b"\x00\x04",
            0x82: b"3021\x00",
            0x83: b"AViatoR\x00",
            0x85: b"\x01\x00\x01",
            0x89: b"PCB-00100 REV2\x00",
            0x8A: b"\x02",
            0x8B: b"\x01",
            0x8F: b"HID Global\x00",
            0x91: b"\x02",
            0x92: b"",
            0x94: b"\x04\x00",
            0x96: b"AVRCC-1.2.0148-20150123T100644-SIMULATED-FLASH",
        }
        self.slot: dict[int, int] = {V.SLOT_EXCHANGE_LEVEL: 0x02, V.SLOT_VOLTAGE_SEQUENCE: 0x00, V.SLOT_OPERATING_MODE: 0x00}
        self.eeprom = bytearray(1024)
        self.rebooted = 0
        self.factory_resets = 0

    def handle(self, payload: bytes, sync_card: "SimulatedMemoryCard | None") -> bytes:
        try:
            root = decode(payload)[0]
        except (ValueError, IndexError):
            return V.TAG_ERROR_RESPONSE.to_bytes(1, "big") + b"\x02\x00\x05" + SW_OK
        if root.tag == V.TAG_READER_INFO_API:
            return self._reader_info(root)
        if root.tag == V.TAG_SYNC_CARD_COMMAND:
            if sync_card is None:
                return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x03]) + SW_OK
            return sync_card.native(root)
        return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x03]) + SW_OK  # NOT_SUPPORTED

    def _reader_info(self, root: TLV) -> bytes:
        if not root.children:
            return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x05]) + SW_OK
        req = root.children[0]
        if req.tag == V.TAG_GET:
            branch = req.children[0] if req.children else None
            if branch is None:
                return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x05]) + SW_OK
            if branch.tag == V.TAG_READER_CAPABILITIES:
                leaves = []
                for leaf in branch.children:
                    if leaf.tag not in self.capabilities:
                        return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x01, 0x04]) + SW_OK
                    leaves.append(tlv(leaf.tag, self.capabilities[leaf.tag]))
                return tlv(V.TAG_RESPONSE_CONSTRUCTED, None, *leaves).encode() + SW_OK
            if branch.tag == V.TAG_CONTACT_SLOT_CONFIG:
                slot = branch.children[0] if branch.children else None
                if slot is None or slot.tag != V.TAG_SLOT_0:
                    return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x04]) + SW_OK
                leaves = []
                for leaf in slot.children:
                    if leaf.tag not in self.slot:
                        return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x01, 0x04]) + SW_OK
                    leaves.append(tlv(leaf.tag, self.slot[leaf.tag]))
                return tlv(V.TAG_RESPONSE_CONSTRUCTED, None, *leaves).encode() + SW_OK
            if branch.tag == V.TAG_READER_EEPROM:
                off = branch.find(0x81)
                ln = branch.find(0x82)
                if off is None or ln is None:
                    return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x02, 0x04]) + SW_OK
                o = int.from_bytes(off.value, "big")
                n = ln.value[0]
                if o + n > len(self.eeprom):
                    return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x02, 0x2F]) + SW_OK
                return tlv(V.TAG_RESPONSE_PRIMITIVE, bytes(self.eeprom[o : o + n])).encode() + SW_OK
            return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x04]) + SW_OK
        if req.tag == V.TAG_SET:
            branch = req.children[0] if req.children else None
            if branch is None:
                return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x05]) + SW_OK
            if branch.tag == V.TAG_CONTACT_SLOT_CONFIG:
                slot = branch.children[0] if branch.children else None
                if slot is None or slot.tag != V.TAG_SLOT_0:
                    return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x04]) + SW_OK
                for leaf in slot.children:
                    if leaf.tag not in self.slot or len(leaf.value) != 1:
                        return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x31]) + SW_OK
                    self.slot[leaf.tag] = leaf.value[0]
                return tlv(V.TAG_RESPONSE_PRIMITIVE, b"").encode() + SW_OK
            if branch.tag == V.TAG_READER_EEPROM:
                off = branch.find(0x81)
                data = branch.find(0x83)
                if off is None or data is None:
                    return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x02, 0x04]) + SW_OK
                o = int.from_bytes(off.value, "big")
                if o + len(data.value) > len(self.eeprom):
                    return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x02, 0x0D]) + SW_OK
                self.eeprom[o : o + len(data.value)] = data.value
                return tlv(V.TAG_RESPONSE_PRIMITIVE, b"").encode() + SW_OK
            if branch.tag == V.TAG_READER_CONFIG_CONTROL:
                for leaf in branch.children:
                    if leaf.tag == 0x80:
                        self.rebooted += 1
                    elif leaf.tag == 0x81:
                        self.factory_resets += 1
                        self.slot = {V.SLOT_EXCHANGE_LEVEL: 0x02, V.SLOT_VOLTAGE_SEQUENCE: 0x00, V.SLOT_OPERATING_MODE: 0x00}
                    else:
                        return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x04]) + SW_OK
                return tlv(V.TAG_RESPONSE_PRIMITIVE, b"").encode() + SW_OK
            if branch.tag == V.TAG_READER_CAPABILITIES:
                return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x15]) + SW_OK  # read only
        return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x03]) + SW_OK


# ---------------------------------------------------------------------------
# Cards
# ---------------------------------------------------------------------------
class SimulatedCard:
    atr: bytes = b""
    protocol: int = C.SCARD_PROTOCOL_T0

    def process(self, apdu: bytes) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    def reset(self) -> None:
        pass


class SimulatedMemoryCard(SimulatedCard):
    """SLE 4442 behaviour (2-wire, 256 bytes, 3-byte PSC, 3 attempts)."""

    atr = bytes.fromhex("3B04A2131091")
    SIZE = 256
    PROTECTABLE = 32

    def __init__(self, psc: bytes = bytes.fromhex("FFFFFF"), manufacturer: bytes | None = None):
        self.memory = bytearray(b"\xff" * self.SIZE)
        if manufacturer is None:
            manufacturer = bytes.fromhex("A2131091") + os.urandom(4) + bytes(range(24))
        self.memory[: len(manufacturer)] = manufacturer[:32]
        self.protection = [False] * self.PROTECTABLE
        for i in range(8):
            self.protection[i] = True  # typical: manufacturer area protected
        self.error_counter = 0x07
        self.psc = bytearray(psc)
        self.verified = False

    def reset(self) -> None:
        self.verified = False

    # -- PC/SC command set -----------------------------------------------------------
    def process(self, apdu: bytes) -> bytes:
        try:
            cmd = CommandAPDU.parse(apdu)
        except ValueError:
            return sw(0x6700)
        if cmd.cla != 0xFF:
            return sw(0x6E00)
        addr = (cmd.p1 << 8) | cmd.p2
        if cmd.ins == 0xB0:
            le = cmd.le or 256
            if addr >= self.SIZE:
                return sw(0x6A82)
            data = bytes(self.memory[addr : addr + le])
            if len(data) < le and cmd.le not in (None, 0, 256):
                return data + sw(0x6282)
            return data + SW_OK
        if cmd.ins == 0xD6:
            if addr + len(cmd.data) > self.SIZE:
                return sw(0x6A82)
            if not self.verified:
                return sw(0x6982)
            for i, b in enumerate(cmd.data):
                a = addr + i
                if a < self.PROTECTABLE and self.protection[a]:
                    return sw(0x6581)
                self.memory[a] = b
            return SW_OK
        if cmd.ins == 0x20:
            if cmd.p1 or cmd.p2:
                return sw(0x6A86)
            return self._verify(cmd.data)
        if cmd.ins == 0x21:
            if len(cmd.data) != 6:
                return sw(0x6700)
            r = self._verify(cmd.data[:3])
            if r != SW_OK:
                return r
            self.psc = bytearray(cmd.data[3:])
            return SW_OK
        if cmd.ins == 0x3A:
            le = cmd.le or 256
            if addr >= self.PROTECTABLE:
                return sw(0x6A82)
            bits = self.protection[addr : addr + le]
            data = bytes(0x01 if b else 0x00 for b in bits)
            return data + (sw(0x6282) if len(bits) < le and cmd.le not in (None, 0, 256) else SW_OK)
        if cmd.ins == 0x30 and cmd.p1 == 0x00 and cmd.p2 == 0x03:
            if len(cmd.data) < 6 or cmd.data[0] != 0x01:
                return sw(0x6A80)
            a = (cmd.data[3] << 8) | cmd.data[4]
            for i, b in enumerate(cmd.data[5:]):
                cur = a + i
                if cur >= self.PROTECTABLE:
                    return cur.to_bytes(2, "big") + sw(0x6A82)
                if self.memory[cur] != b:
                    return cur.to_bytes(2, "big") + sw(0x6F00)
                if not self.protection[cur]:
                    if not self.verified:
                        return cur.to_bytes(2, "big") + sw(0x6982)
                    self.protection[cur] = True
            return SW_OK
        if cmd.ins == 0x30 and cmd.p2 in (0x04, 0x05, 0x06):
            return sw(0x6F00)  # I2C commands on a 2WBP card: unknown card protocol
        return sw(0x6D00)

    def _verify(self, pin: bytes) -> bytes:
        if len(pin) != 3:
            return sw(0x6700)
        if self.error_counter & 0x07 == 0:
            return sw(0x6983)
        if bytes(pin) == bytes(self.psc):
            self.error_counter = 0x07
            self.verified = True
            return SW_OK
        # clear the lowest set bit
        ec = self.error_counter & 0x07
        ec &= ec - 1
        self.error_counter = ec
        remaining = bin(ec).count("1")
        if remaining == 0:
            return sw(0x6983)
        return sw(0x63C0 | remaining)

    # -- raw 2WBP (vendor A6/A0) -----------------------------------------------------------
    def native(self, root: TLV) -> bytes:
        bus = root.children[0] if root.children else None
        if bus is None or bus.tag != V.TAG_2WBP or len(bus.value) != 3:
            return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x05]) + SW_OK
        ctrl, addr, data = bus.value
        out = b""
        if ctrl == V.W2_READ_MAIN:
            out = bytes(self.memory[addr : addr + 1])
        elif ctrl == V.W2_UPDATE_MAIN:
            if self.verified and not (addr < self.PROTECTABLE and self.protection[addr]):
                self.memory[addr] = data
        elif ctrl == V.W2_READ_PROTECTION:
            # 4 bytes, LSB first, bit set = protected
            value = 0
            for i, p in enumerate(self.protection):
                if p:
                    value |= 1 << i
            out = value.to_bytes(4, "little")
        elif ctrl == V.W2_READ_SECURITY:
            sec = bytes([self.error_counter]) + (bytes(self.psc) if self.verified else b"\x00\x00\x00")
            out = sec[addr & 0x03 : (addr & 0x03) + 1]
        else:
            return bytes([V.TAG_ERROR_RESPONSE, 0x02, 0x00, 0x03]) + SW_OK
        return tlv(V.TAG_RESPONSE_CONSTRUCTED, None, tlv(V.TAG_2WBP, out)).encode() + SW_OK


@dataclass
class SimFile:
    fid: int
    data: bytearray
    read_needs_pin: bool = False
    write_needs_pin: bool = True


class SimulatedIsoCard(SimulatedCard):
    """A small ISO 7816-4 file-system card with PIN, GET CHALLENGE and INTERNAL AUTHENTICATE.

    ``t0_style=True`` makes case-4 commands answer ``61 xx`` and wrong Le ``6C xx``
    so the T=0 conveniences in ``transmit_apdu`` get exercised.
    """

    atr = bytes.fromhex("3BD518FF8191FE1FC38073C821100A")  # T=0/T=1 CPU card style ATR
    protocol = C.SCARD_PROTOCOL_T1
    AID = bytes.fromhex("A000000003021001")

    def __init__(self, pin: bytes = b"1234", auth_key: bytes = b"\x00" * 16, serial: bytes | None = None,
                 t0_style: bool = False, files: dict[int, bytes] | None = None):
        self.pin = bytes(pin)
        self.pin_tries = 3
        self.pin_ok = False
        self.auth_key = bytes(auth_key)
        self.serial = serial or os.urandom(8)
        self.t0_style = t0_style
        self.files: dict[int, SimFile] = {
            0x0001: SimFile(0x0001, bytearray(b"\x00" * 128), False, True),  # credential EF
            0x0002: SimFile(0x0002, bytearray(b"hello ISO 7816 " * 20), False, True),
            0x0003: SimFile(0x0003, bytearray(self.serial), False, True),
        }
        if files:
            for fid, content in files.items():
                self.files[fid] = SimFile(fid, bytearray(content))
        self.current: SimFile | None = None
        self.selected_aid = False
        self.challenge: bytes | None = None
        self._pending: bytes | None = None

    def reset(self) -> None:
        self.pin_ok = False
        self.current = None
        self.selected_aid = False
        self.challenge = None
        self._pending = None

    def process(self, apdu: bytes) -> bytes:
        try:
            cmd = CommandAPDU.parse(apdu)
        except ValueError:
            return sw(0x6700)
        if cmd.cla == 0xFF:
            return sw(0x6E00)
        if cmd.ins == 0xC0:  # GET RESPONSE
            if self._pending is None:
                return sw(0x6985)
            data, self._pending = self._pending, None
            le = cmd.le or 256
            if le < len(data):
                self._pending = data[le:]
                return data[:le] + sw(0x6100 | min(len(self._pending), 255))
            return data + SW_OK
        resp = self._execute(cmd)
        if self.t0_style and len(resp) > 2 and resp[-2:] == SW_OK:
            data = resp[:-2]
            if cmd.le is None or cmd.data:
                # case 3/4 under T=0: park data, announce 61 xx
                self._pending = data
                return sw(0x6100 | min(len(data), 255))
            le = cmd.le or 256
            if data and le != len(data):
                return sw(0x6C00 | (len(data) & 0xFF))
        return resp

    def _execute(self, cmd: CommandAPDU) -> bytes:
        if cmd.cla & 0xF0 not in (0x00, 0x80):
            return sw(0x6E00)
        if cmd.ins == 0xA4:
            return self._select(cmd)
        if cmd.ins == 0xB0:
            if self.current is None:
                return sw(0x6986)
            if self.current.read_needs_pin and not self.pin_ok:
                return sw(0x6982)
            off = ((cmd.p1 & 0x7F) << 8) | cmd.p2
            if cmd.p1 & 0x80:
                return sw(0x6A82)  # no SFI support in the simulation
            if off > len(self.current.data):
                return sw(0x6B00)
            le = cmd.le or 256
            data = bytes(self.current.data[off : off + le])
            if len(data) < le and cmd.le not in (None, 0, 256):
                return data + sw(0x6282)
            return data + SW_OK
        if cmd.ins == 0xD6:
            if self.current is None:
                return sw(0x6986)
            if self.current.write_needs_pin and not self.pin_ok:
                return sw(0x6982)
            off = ((cmd.p1 & 0x7F) << 8) | cmd.p2
            if off + len(cmd.data) > len(self.current.data):
                return sw(0x6B00)
            self.current.data[off : off + len(cmd.data)] = cmd.data
            return SW_OK
        if cmd.ins == 0x20:
            if not cmd.data:
                return sw(0x6983) if self.pin_tries == 0 else sw(0x63C0 | self.pin_tries)
            if self.pin_tries == 0:
                return sw(0x6983)
            if cmd.data.rstrip(b"\xff") == self.pin:
                self.pin_ok = True
                self.pin_tries = 3
                return SW_OK
            self.pin_tries -= 1
            return sw(0x6983) if self.pin_tries == 0 else sw(0x63C0 | self.pin_tries)
        if cmd.ins == 0x24:
            n = len(self.pin)
            if len(cmd.data) < n or cmd.data[:n] != self.pin:
                self.pin_tries = max(0, self.pin_tries - 1)
                return sw(0x63C0 | self.pin_tries)
            self.pin = bytes(cmd.data[n:])
            return SW_OK
        if cmd.ins == 0x84:
            self.challenge = os.urandom(cmd.le or 8)
            return self.challenge + SW_OK
        if cmd.ins == 0x88:
            # response = HMAC-SHA256(key, host challenge || card serial)
            mac = hmac.new(self.auth_key, cmd.data + self.serial, hashlib.sha256).digest()
            return mac + SW_OK
        if cmd.ins == 0xCA:
            tag = (cmd.p1 << 8) | cmd.p2
            if tag == 0x9F7F:
                return self.serial + SW_OK
            if tag == 0x004F:
                return self.AID + SW_OK
            return sw(0x6A88)
        if cmd.ins == 0xB2 or cmd.ins == 0xDC or cmd.ins == 0xE2:
            return sw(0x6981)
        return sw(0x6D00)

    def _select(self, cmd: CommandAPDU) -> bytes:
        if cmd.p1 == 0x04:
            if cmd.data == self.AID:
                self.selected_aid = True
                self.current = None
                fci = tlv(0x6F, None, tlv(0x84, self.AID), tlv(0xA5, None, tlv(0x50, b"SIM ACCESS")))
                return (fci.encode() if (cmd.p2 & 0x0C) != 0x0C else b"") + SW_OK
            return sw(0x6A82)
        if cmd.p1 in (0x00, 0x02):
            if len(cmd.data) != 2:
                return sw(0x6A87) if cmd.data else self._select_mf()
            fid = int.from_bytes(cmd.data, "big")
            if fid == 0x3F00:
                return self._select_mf()
            f = self.files.get(fid)
            if f is None:
                return sw(0x6A82)
            self.current = f
            fcp = tlv(0x62, None, tlv(0x80, len(f.data).to_bytes(2, "big")), tlv(0x82, b"\x01"),
                      tlv(0x83, fid.to_bytes(2, "big")))
            return (fcp.encode() if (cmd.p2 & 0x0C) != 0x0C else b"") + SW_OK
        if cmd.p1 == 0x01 and cmd.data == b"\x3f\x00":
            return self._select_mf()
        return sw(0x6A86)

    def _select_mf(self) -> bytes:
        self.current = None
        self.selected_aid = False
        return tlv(0x62, None, tlv(0x82, b"\x38"), tlv(0x83, b"\x3f\x00")).encode() + SW_OK


# ---------------------------------------------------------------------------
# Reader + channel
# ---------------------------------------------------------------------------
class SimulatedChannel:
    """CardChannel implementation talking to a SimulatedReader."""

    def __init__(self, reader: "SimulatedReader"):
        self.reader = reader
        self.trace = False
        self.log: list[tuple[bytes, bytes]] = []

    @property
    def atr(self) -> bytes:
        return self.reader.card.atr if self.reader.card else b""

    @property
    def protocol(self) -> int:
        return self.reader.card.protocol if self.reader.card else C.SCARD_PROTOCOL_UNDEFINED

    @property
    def protocol_name(self) -> str:
        return C.PROTOCOL_NAMES.get(self.protocol, "?")

    @property
    def parsed_atr(self):
        from .atr import parse_atr

        return parse_atr(self.atr)

    def transmit(self, data: bytes) -> bytes:
        resp = self.reader.transmit(bytes(data))
        self.log.append((bytes(data), resp))
        if self.trace:
            print(f">> {bytes(data).hex(' ').upper()}\n<< {resp.hex(' ').upper()}")
        return resp

    def control(self, code: int, data: bytes = b"") -> bytes:
        return self.reader.control(code, bytes(data))

    def apdu(self, command, **kw):
        from .apdu import transmit_apdu

        return transmit_apdu(self.transmit, command, **kw)

    def reconnect(self, reset: bool = True, **_):
        if reset and self.reader.card:
            self.reader.card.reset()
        return self.protocol

    def disconnect(self, *_):
        pass

    def features(self):
        from .reader import Feature

        return {C.FEATURE_CCID_ESC_COMMAND: Feature(C.FEATURE_CCID_ESC_COMMAND, "FEATURE_CCID_ESC_COMMAND", C.IOCTL_CCID_ESCAPE)}

    def escape(self, payload: bytes) -> bytes:
        return self.control(C.IOCTL_CCID_ESCAPE, payload)

    def attributes(self) -> dict[str, str]:
        return {"VENDOR_NAME": "HID Global (simulated)", "VENDOR_IFD_TYPE": "OMNIKEY 3021",
                "ATR_STRING": self.atr.hex(" ").upper()}

    def legacy_firmware_version(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass


class SimulatedReader:
    name = "HID Global OMNIKEY 3x21 Smart Card Reader (simulated) 00 00"

    def __init__(self, card: SimulatedCard | None = None):
        self.firmware = SimulatedFirmware()
        self.card: SimulatedCard | None = card

    # -- card handling ----------------------------------------------------------------
    def insert(self, card: SimulatedCard) -> None:
        self.card = card
        card.reset()

    def remove(self) -> None:
        self.card = None

    def is_card_present(self) -> bool:
        return self.card is not None

    def wait_for_card(self, timeout_s: float | None = None):
        if self.card is None:
            raise NoCardError("simulated reader: no card inserted")
        return self.card

    def wait_for_removal(self, timeout_s: float | None = None):
        return None

    def connect(self, *args, **kwargs) -> SimulatedChannel:
        if self.card is None:
            raise NoCardError("simulated reader: no card inserted")
        return SimulatedChannel(self)

    def connect_direct(self) -> SimulatedChannel:
        return SimulatedChannel(self)

    def close(self) -> None:
        pass

    # -- transport ---------------------------------------------------------------------------
    def _vendor(self, apdu: bytes) -> bytes:
        try:
            cmd = CommandAPDU.parse(apdu)
        except ValueError:
            return sw(0x6700)
        if (cmd.p1, cmd.p2) != (V.VENDOR_P1, V.VENDOR_P2):
            return sw(0x6A86)
        sync = self.card if isinstance(self.card, SimulatedMemoryCard) else None
        return self.firmware.handle(cmd.data, sync)

    def transmit(self, apdu: bytes) -> bytes:
        if self.card is None:
            raise NoCardError("simulated reader: card removed")
        if len(apdu) >= 4 and apdu[0] == V.VENDOR_CLA and apdu[1] == V.VENDOR_INS:
            return self._vendor(apdu)
        return self.card.process(apdu)

    def control(self, code: int, data: bytes = b"") -> bytes:
        if code == C.CM_IOCTL_GET_FEATURE_REQUEST:
            return bytes([C.FEATURE_CCID_ESC_COMMAND, 0x04]) + C.IOCTL_CCID_ESCAPE.to_bytes(4, "big")
        if code == C.IOCTL_CCID_ESCAPE:
            if len(data) >= 4 and data[0] == V.VENDOR_CLA and data[1] == V.VENDOR_INS:
                return self._vendor(data)
            return sw(0x6D00)
        raise NoCardError(f"simulated reader: unsupported control code 0x{code:08X}")
