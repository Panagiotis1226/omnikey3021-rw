"""OMNIKEY vendor specific command set (PLT-03099 chapters 6, 8.2 and 9).

Everything goes through the generic vendor APDU::

    FF 70 07 6B Lc <DER-TLV payload> Le

P1P2 = 076Bh is HID/OMNIKEY's USB vendor ID.  The payload is an ASN.1 tree:

    A2  readerInformationApi
        A0  GET             A1  SET
            A0  readerCapabilities (read only)   80 tlvVersion, 81 deviceID, 82 productName,
                                                 83 productPlatform, 85 firmwareVersion,
                                                 89 hardwareVersion, 8A hostInterfaces,
                                                 8B numberOfContactSlots, 8F vendorName,
                                                 91 exchangeLevel, 92 serialNumber,
                                                 94 sizeOfUserEEProm, 96 firmwareLabel
            A3  contactSlotConfiguration         (A0 = slot) 80 exchangeLevel, 82 voltageSequence,
                                                 83 operatingMode
            A7  readerEEPROM                     81 eepromOffset, 82 eepromRdLength, 83 eepromWrData
            A9  readerConfigurationControl       80 rebootDevice, 81 restoreFactoryDefaults
    A6  synchronousCardCommand
        A0  2WBP read/write    A1  3WBP read/write    A2  I2C read/write

Responses: ``9D`` (primitive) or ``BD`` (constructed) carry data; ``9E 02 cycle code``
is a firmware error.  SW1SW2 is 9000 for both success and firmware-level errors.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .apdu import CommandAPDU, ResponseAPDU
from .channel import CardChannel
from .errors import CardError, VendorError
from .tlv import TLV, decode, tlv

VENDOR_CLA = 0xFF
VENDOR_INS = 0x70
VENDOR_P1 = 0x07  # VID 076Bh high byte
VENDOR_P2 = 0x6B  # VID 076Bh low byte

TAG_READER_INFO_API = 0xA2
TAG_DEVICE_SPECIFIC = 0xBC
TAG_RESPONSE_PRIMITIVE = 0x9D
TAG_RESPONSE_CONSTRUCTED = 0xBD
TAG_ERROR_RESPONSE = 0x9E
TAG_SYNC_CARD_COMMAND = 0xA6

TAG_GET = 0xA0
TAG_SET = 0xA1
TAG_READER_CAPABILITIES = 0xA0
TAG_CONTACT_SLOT_CONFIG = 0xA3
TAG_SLOT_0 = 0xA0
TAG_READER_EEPROM = 0xA7
TAG_READER_CONFIG_CONTROL = 0xA9

TAG_2WBP = 0xA0
TAG_3WBP = 0xA1
TAG_I2C = 0xA2

ERROR_CYCLES = {
    0: "HID proprietary command APDU",
    1: "HID proprietary response APDU",
    2: "HID read or write EEPROM structure",
}
ERROR_CODES = {
    0x03: "NOT_SUPPORTED",
    0x04: "TLV_NOT_FOUND",
    0x05: "TLV_MALFORMED",
    0x06: "ISO_EXCEPTION",
    0x0B: "PERSISTENT_TRANSACTION_ERROR",
    0x0C: "PERSISTENT_WRITE_ERROR",
    0x0D: "OUT_OF_PERSISTENT_MEMORY",
    0x0F: "PERSISTENT_MEMORY_OBJECT_NOT_FOUND",
    0x11: "INVALID_STORE_OPERATION",
    0x13: "TLV_INVALID_STRENGTH",
    0x14: "TLV_INSUFFICIENT_BUFFER",
    0x15: "DATA_OBJECT_READONLY",
    0x1F: "APPLICATION_EXCEPTION",
    0x2A: "MEDIA_TRANSMIT_EXCEPTION",
    0x2B: "SAM_INSUFFICIENT_MSGHEADER",
    0x2F: "TLV_INVALID_INDEX",
    0x30: "SECURITY_STATUS_NOT_SATISFIED",
    0x31: "TLV_INVALID_VALUE",
    0x32: "TLV_INVALID_TREE",
    0x40: "RANDOM_INVALID",
    0x41: "OBJECT_NOT_FOUND",
}

# readerCapabilities leaves: tag -> (name, type)
CAPABILITY_TAGS: dict[int, tuple[str, str]] = {
    0x80: ("tlvVersion", "u8"),
    0x81: ("deviceID", "hex"),
    0x82: ("productName", "str"),
    0x83: ("productPlatform", "str"),
    0x85: ("firmwareVersion", "version"),
    0x89: ("hardwareVersion", "str"),
    0x8A: ("hostInterfaces", "hostif"),
    0x8B: ("numberOfContactSlots", "u8"),
    0x8F: ("vendorName", "str"),
    0x91: ("exchangeLevel", "exchange"),
    0x92: ("serialNumber", "hex"),
    0x94: ("sizeOfUserEEProm", "u16"),
    0x96: ("firmwareLabel", "str"),
}

# contactSlotConfiguration leaves
SLOT_EXCHANGE_LEVEL = 0x80
SLOT_VOLTAGE_SEQUENCE = 0x82
SLOT_OPERATING_MODE = 0x83

EXCHANGE_LEVELS = {0x01: "TPDU", 0x02: "APDU", 0x03: "Extended APDU", 0x04: "Extended APDU"}
EXCHANGE_LEVEL_TPDU = 0x01
EXCHANGE_LEVEL_APDU = 0x02
EXCHANGE_LEVEL_EXTENDED = 0x04  # section 9.2 value; section 5.3 lists 03h for the same level

OPERATING_MODES = {0x00: "ISO/IEC 7816", 0x01: "EMVCo"}
OPERATING_MODE_ISO = 0x00
OPERATING_MODE_EMVCO = 0x01

VOLTAGE_CODES = {1: "1.8V", 2: "3V", 3: "5V"}
VOLTAGE_BY_NAME = {"1.8": 1, "1.8v": 1, "3": 2, "3v": 2, "5": 3, "5v": 3}


def encode_voltage_sequence(sequence: list[str] | None) -> int:
    """Encode e.g. ["5V", "3V", "1.8V"] -> 0x1B (PLT-03099 section 5.2).

    The class tried first occupies bits 1-0, the second bits 3-2, the third bits 5-4
    (1Bh = 00 01 10 11 = 5V -> 3V -> 1.8V).  ``None``/[] = automatic selection.
    """
    if not sequence:
        return 0
    if len(sequence) > 3:
        raise ValueError("at most three voltage classes")
    value = 0
    for i, step in enumerate(sequence):
        code = VOLTAGE_BY_NAME.get(step.lower().replace(" ", ""))
        if code is None:
            raise ValueError(f"unknown voltage class {step!r}; use 5V, 3V or 1.8V")
        value |= code << (2 * i)
    return value


def decode_voltage_sequence(value: int) -> list[str]:
    if value & 0x3F == 0:
        return []
    out = []
    for shift in (0, 2, 4):
        code = (value >> shift) & 0x3
        if code:
            out.append(VOLTAGE_CODES[code])
    return out


def build_vendor_apdu(payload: TLV | bytes, le: int | None = 0) -> bytes:
    data = payload.encode() if isinstance(payload, TLV) else bytes(payload)
    return CommandAPDU(VENDOR_CLA, VENDOR_INS, VENDOR_P1, VENDOR_P2, data, le).to_bytes()


@dataclass
class VendorResponse:
    raw: bytes
    tlv: TLV | None
    sw: int

    @property
    def data(self) -> bytes:
        """Payload of a primitive response (9D) or the concatenated children of a BD."""
        if self.tlv is None:
            return b""
        return self.tlv.value

    def leaf(self, tag: int) -> bytes | None:
        if self.tlv is None:
            return None
        if self.tlv.tag == tag:
            return self.tlv.value
        found = self.tlv.find_deep(tag)
        return found.value if found else None


def parse_vendor_response(raw: bytes) -> VendorResponse:
    resp = ResponseAPDU.from_bytes(raw)
    # The guide's 2WBP examples show SW 99 00 for a successful native exchange;
    # treat it as success alongside 90 00.
    if resp.sw not in (0x9000, 0x9900):
        raise CardError(resp.sw1, resp.sw2, command=None)
    items = decode(resp.data) if resp.data else []
    if not items:
        return VendorResponse(raw, None, resp.sw)
    first = items[0]
    if first.tag == TAG_ERROR_RESPONSE:
        cycle = first.value[0] if len(first.value) > 0 else 0xFF
        code = first.value[1] if len(first.value) > 1 else 0xFF
        raise VendorError(cycle, code)
    return VendorResponse(raw, first, resp.sw)


def vendor_command(channel: CardChannel, payload: TLV | bytes, *, via_control: bool = False,
                   control_code: int | None = None) -> VendorResponse:
    """Send a vendor command.  ``via_control=True`` uses the CCID escape (no card needed)."""
    apdu = build_vendor_apdu(payload)
    if via_control:
        from . import pcsc_constants as C

        raw = channel.control(control_code if control_code is not None else C.IOCTL_CCID_ESCAPE, apdu)
    else:
        raw = channel.transmit(apdu)
    return parse_vendor_response(raw)


# ---------------------------------------------------------------------------
# Reader information / configuration
# ---------------------------------------------------------------------------
class ReaderConfig:
    """readerInformationApi (tag A2) GET/SET helpers."""

    def __init__(self, channel: CardChannel, via_control: bool = False):
        self.channel = channel
        self.via_control = via_control

    def _send(self, payload: TLV) -> VendorResponse:
        return vendor_command(self.channel, payload, via_control=self.via_control)

    # -- readerCapabilities ---------------------------------------------------
    def get_capability_raw(self, tag: int) -> bytes:
        payload = tlv(TAG_READER_INFO_API, None, tlv(TAG_GET, None, tlv(TAG_READER_CAPABILITIES, None, tlv(tag))))
        resp = self._send(payload)
        value = resp.leaf(tag)
        if value is None:
            raise VendorError(1, 0x04)
        return value

    def get_capability(self, tag: int) -> Any:
        name, kind = CAPABILITY_TAGS.get(tag, (f"tag{tag:02X}", "hex"))
        return _decode_value(kind, self.get_capability_raw(tag))

    def capabilities(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for tag, (name, kind) in CAPABILITY_TAGS.items():
            try:
                out[name] = _decode_value(kind, self.get_capability_raw(tag))
            except (CardError, VendorError) as exc:
                out[name] = f"<unavailable: {exc}>"
        return out

    # -- contactSlotConfiguration ------------------------------------------------
    def get_slot_setting_raw(self, tag: int) -> bytes:
        payload = tlv(TAG_READER_INFO_API, None,
                      tlv(TAG_GET, None, tlv(TAG_CONTACT_SLOT_CONFIG, None, tlv(TAG_SLOT_0, None, tlv(tag)))))
        resp = self._send(payload)
        value = resp.leaf(tag)
        if value is None:
            raise VendorError(1, 0x04)
        return value

    def set_slot_setting_raw(self, tag: int, value: int) -> None:
        payload = tlv(TAG_READER_INFO_API, None,
                      tlv(TAG_SET, None, tlv(TAG_CONTACT_SLOT_CONFIG, None, tlv(TAG_SLOT_0, None, tlv(tag, value)))))
        self._send(payload)

    def get_exchange_level(self) -> int:
        return self.get_slot_setting_raw(SLOT_EXCHANGE_LEVEL)[0]

    def set_exchange_level(self, level: int) -> None:
        if level not in EXCHANGE_LEVELS:
            raise ValueError("exchange level must be 1 (TPDU), 2 (APDU) or 4 (extended APDU)")
        self.set_slot_setting_raw(SLOT_EXCHANGE_LEVEL, level)

    def get_voltage_sequence(self) -> int:
        return self.get_slot_setting_raw(SLOT_VOLTAGE_SEQUENCE)[0]

    def set_voltage_sequence(self, value: int) -> None:
        if not 0 <= value <= 0x3F:
            raise ValueError("voltage sequence byte must be 0..0x3F")
        self.set_slot_setting_raw(SLOT_VOLTAGE_SEQUENCE, value)

    def get_operating_mode(self) -> int:
        return self.get_slot_setting_raw(SLOT_OPERATING_MODE)[0]

    def set_operating_mode(self, mode: int) -> None:
        if mode not in OPERATING_MODES:
            raise ValueError("operating mode must be 0 (ISO) or 1 (EMVCo)")
        self.set_slot_setting_raw(SLOT_OPERATING_MODE, mode)

    def slot_configuration(self) -> dict[str, str]:
        out: dict[str, str] = {}
        try:
            lvl = self.get_exchange_level()
            out["exchangeLevel"] = f"{EXCHANGE_LEVELS.get(lvl, '?')} ({lvl})"
        except (CardError, VendorError) as exc:
            out["exchangeLevel"] = f"<unavailable: {exc}>"
        try:
            v = self.get_voltage_sequence()
            seq = decode_voltage_sequence(v)
            out["voltageSequence"] = (" -> ".join(seq) if seq else "automatic (driver decides)") + f" (0x{v:02X})"
        except (CardError, VendorError) as exc:
            out["voltageSequence"] = f"<unavailable: {exc}>"
        try:
            m = self.get_operating_mode()
            out["operatingMode"] = f"{OPERATING_MODES.get(m, '?')} ({m})"
        except (CardError, VendorError) as exc:
            out["operatingMode"] = f"<unavailable: {exc}>"
        return out

    # -- user EEPROM (1024 bytes) ---------------------------------------------------
    def read_eeprom(self, offset: int, length: int) -> bytes:
        if not 0 <= offset <= 0xFFFF:
            raise ValueError("offset out of range")
        if not 1 <= length <= 0xFF:
            raise ValueError("length must be 1..255")
        payload = tlv(TAG_READER_INFO_API, None,
                      tlv(TAG_GET, None, tlv(TAG_READER_EEPROM, None,
                                             tlv(0x81, offset.to_bytes(2, "big")), tlv(0x82, length))))
        resp = self._send(payload)
        return resp.data

    def write_eeprom(self, offset: int, data: bytes) -> None:
        if not 0 <= offset <= 0xFFFF:
            raise ValueError("offset out of range")
        if not 1 <= len(data) <= 200:
            raise ValueError("write 1..200 bytes per command")
        payload = tlv(TAG_READER_INFO_API, None,
                      tlv(TAG_SET, None, tlv(TAG_READER_EEPROM, None,
                                             tlv(0x81, offset.to_bytes(2, "big")), tlv(0x83, bytes(data)))))
        self._send(payload)

    # -- readerConfigurationControl -----------------------------------------------------
    def reboot(self) -> None:
        payload = tlv(TAG_READER_INFO_API, None, tlv(TAG_SET, None, tlv(TAG_READER_CONFIG_CONTROL, None, tlv(0x80, 0))))
        self._send(payload)

    def restore_factory_defaults(self) -> None:
        payload = tlv(TAG_READER_INFO_API, None, tlv(TAG_SET, None, tlv(TAG_READER_CONFIG_CONTROL, None, tlv(0x81, 0))))
        self._send(payload)


def _decode_value(kind: str, value: bytes) -> Any:
    if kind == "u8":
        return value[0] if value else None
    if kind == "u16":
        return int.from_bytes(value, "big") if value else None
    if kind == "str":
        return value.split(b"\x00")[0].decode("ascii", "replace")
    if kind == "version":
        return ".".join(str(b) for b in value) if value else ""
    if kind == "hostif":
        flags = value[0] if value else 0
        names = [n for bit, n in ((0x02, "USB"),) if flags & bit]
        return ", ".join(names) or f"0x{flags:02X}"
    if kind == "exchange":
        return EXCHANGE_LEVELS.get(value[0], f"0x{value[0]:02X}") if value else None
    return value.hex().upper()


# ---------------------------------------------------------------------------
# Native synchronous card commands (section 8.2)
# ---------------------------------------------------------------------------
def sync_native(channel: CardChannel, bus_tag: int, command: bytes) -> bytes:
    """Send a raw bus-protocol command; returns the bytes the card clocked out."""
    payload = tlv(TAG_SYNC_CARD_COMMAND, None, tlv(bus_tag, bytes(command)))
    resp = vendor_command(channel, payload)
    data = resp.leaf(bus_tag)
    return data if data is not None else b""


def sync_2wbp(channel: CardChannel, control: int, address: int, data: int = 0) -> bytes:
    """2-wire bus protocol (SLE 4432/4442) 3-byte command: control, address, data."""
    return sync_native(channel, TAG_2WBP, bytes([control & 0xFF, address & 0xFF, data & 0xFF]))


def sync_3wbp(channel: CardChannel, control: int, address: int, data: int = 0) -> bytes:
    """3-wire bus protocol (SLE 4418/4428) 3-byte command.

    ``control`` carries A9 A8 (bits 7-6) and S5..S0; ``address`` carries A7..A0.
    """
    return sync_native(channel, TAG_3WBP, bytes([control & 0xFF, address & 0xFF, data & 0xFF]))


def sync_i2c(channel: CardChannel, address_length: int, count: int, device_address: int,
             sub1: int = 0, sub2: int = 0, data: bytes = b"") -> bytes:
    """Raw I2C transaction: 5 byte header (+ data for writes); max 32 bytes per transfer."""
    if address_length not in (1, 2, 3):
        raise ValueError("address_length must be 1, 2 or 3")
    if not 0 <= count <= 32:
        raise ValueError("count must be 0..32")
    cmd = bytes([address_length, count, device_address & 0xFF, sub1 & 0xFF, sub2 & 0xFF]) + bytes(data)
    return sync_native(channel, TAG_I2C, cmd)


# 2WBP control bytes (SLE 4432/4442 datasheet)
W2_READ_MAIN = 0x30
W2_UPDATE_MAIN = 0x38
W2_READ_PROTECTION = 0x34
W2_WRITE_PROTECTION = 0x3C
W2_READ_SECURITY = 0x31      # SLE 4442 only
W2_UPDATE_SECURITY = 0x39    # SLE 4442 only
W2_COMPARE_VERIFICATION = 0x33  # SLE 4442 only

# 3WBP control words (SLE 4418/4428 datasheet), A9A8 = 00; OR in (addr >> 8) << 6
W3_READ_9BIT = 0x0C          # data + protect bit
W3_READ_8BIT = 0x0E          # data only
W3_WRITE_WITH_PROTECT = 0x31
W3_WRITE_NO_PROTECT = 0x33
W3_WRITE_PROTECT_COMPARE = 0x30
W3_WRITE_ERROR_COUNTER = 0x32   # address 0x3FD
W3_VERIFY_PIN = 0x35            # addresses 0x3FE / 0x3FF
