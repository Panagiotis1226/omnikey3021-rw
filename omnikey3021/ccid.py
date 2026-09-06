"""USB CCID (Integrated Circuit(s) Cards Interface Device) support.

The OMNIKEY 3021 enumerates as a CCID 1.1 class device (bInterfaceClass 0x0B)
and is driven by the OS CCID driver; the host talks PC/SC on top of it.  This
module exposes the CCID layer itself:

* ``parse_class_descriptor``   - decode the 54-byte CCID class descriptor
  (voltages, clocks, data rates, IFSD, exchange level, automatic features ...)
* ``find_usb_ccid_devices``    - locate CCID interfaces via sysfs on Linux and
  read their descriptors without libusb
* ``parse_tlv_properties``     - PC/SC part 10 GET_TLV_PROPERTIES (USB VID/PID,
  firmware id, max APDU size ...) - works on every OS through SCardControl
* CCID bulk message constants for interpreting escape traffic
"""

from __future__ import annotations

import glob
import os
import struct
from dataclasses import dataclass, field

HID_VENDOR_ID = 0x076B
OMNIKEY_3021_PRODUCT_ID = 0x3021
OMNIKEY_3x21_PRODUCT_IDS = {0x3021: "OMNIKEY 3021", 0x3121: "OMNIKEY 3121", 0x302A: "OMNIKEY 3021 (AViatoR)",
                            0x312A: "OMNIKEY 3121 (AViatoR)", 0x502A: "OMNIKEY 3121 SC", 0x6121: "OMNIKEY 6121"}

CCID_CLASS = 0x0B
CCID_DESCRIPTOR_TYPE = 0x21
CCID_DESCRIPTOR_LENGTH = 0x36

# CCID rev 1.1 bulk-out / bulk-in message types
PC_TO_RDR = {
    0x62: "PC_to_RDR_IccPowerOn", 0x63: "PC_to_RDR_IccPowerOff", 0x65: "PC_to_RDR_GetSlotStatus",
    0x6F: "PC_to_RDR_XfrBlock", 0x6C: "PC_to_RDR_GetParameters", 0x6D: "PC_to_RDR_ResetParameters",
    0x61: "PC_to_RDR_SetParameters", 0x6B: "PC_to_RDR_Escape", 0x6E: "PC_to_RDR_IccClock",
    0x6A: "PC_to_RDR_T0APDU", 0x69: "PC_to_RDR_Secure", 0x71: "PC_to_RDR_Mechanical", 0x72: "PC_to_RDR_Abort",
    0x73: "PC_to_RDR_SetDataRateAndClockFrequency",
}
RDR_TO_PC = {
    0x80: "RDR_to_PC_DataBlock", 0x81: "RDR_to_PC_SlotStatus", 0x82: "RDR_to_PC_Parameters",
    0x83: "RDR_to_PC_Escape", 0x84: "RDR_to_PC_DataRateAndClockFrequency", 0x50: "RDR_to_PC_NotifySlotChange",
    0x51: "RDR_to_PC_HardwareError",
}

FEATURE_BITS = {
    0x00000002: "Automatic parameter configuration based on ATR",
    0x00000004: "Automatic activation of ICC on inserting",
    0x00000008: "Automatic ICC voltage selection",
    0x00000010: "Automatic ICC clock frequency change",
    0x00000020: "Automatic baud rate change",
    0x00000040: "Automatic parameters negotiation (PPS by reader)",
    0x00000080: "Automatic PPS made by the CCID",
    0x00000100: "CCID can set ICC in clock stop mode",
    0x00000200: "NAD value other than 00 accepted (T=1)",
    0x00000400: "Automatic IFSD exchange as first exchange (T=1)",
    0x00010000: "TPDU level exchanges",
    0x00020000: "Short APDU level exchange",
    0x00040000: "Short and extended APDU level exchange",
    0x00100000: "USB wake up signaling on card insertion/removal",
}
EXCHANGE_LEVEL_MASK = 0x00070000
PROTOCOL_BITS = {0x01: "T=0", 0x02: "T=1"}
SYNC_PROTOCOL_BITS = {0x01: "2-wire (SLE 4432/4442)", 0x02: "3-wire (SLE 4418/4428)", 0x04: "I2C"}
VOLTAGE_BITS = {0x01: "5.0V", 0x02: "3.0V", 0x04: "1.8V"}
MECHANICAL_BITS = {0x01: "card accept", 0x02: "card ejection", 0x04: "card capture", 0x08: "card lock/unlock"}
PIN_BITS = {0x01: "PIN verification", 0x02: "PIN modification"}


@dataclass
class CcidDescriptor:
    raw: bytes
    bcd_ccid: int
    max_slot_index: int
    voltage_support: int
    protocols: int
    default_clock_khz: int
    maximum_clock_khz: int
    num_clocks_supported: int
    data_rate_bps: int
    max_data_rate_bps: int
    num_data_rates_supported: int
    max_ifsd: int
    synch_protocols: int
    mechanical: int
    features: int
    max_ccid_message_length: int
    class_get_response: int
    class_envelope: int
    lcd_layout: int
    pin_support: int
    max_ccid_busy_slots: int

    @property
    def version(self) -> str:
        return f"{self.bcd_ccid >> 8}.{(self.bcd_ccid >> 4) & 0xF}{self.bcd_ccid & 0xF}"

    @property
    def voltages(self) -> list[str]:
        return [n for b, n in VOLTAGE_BITS.items() if self.voltage_support & b]

    @property
    def protocol_names(self) -> list[str]:
        return [n for b, n in PROTOCOL_BITS.items() if self.protocols & b]

    @property
    def synchronous_protocols(self) -> list[str]:
        return [n for b, n in SYNC_PROTOCOL_BITS.items() if self.synch_protocols & b]

    @property
    def exchange_level(self) -> str:
        lvl = self.features & EXCHANGE_LEVEL_MASK
        return {0: "character", 0x00010000: "TPDU", 0x00020000: "short APDU", 0x00040000: "short + extended APDU"}.get(
            lvl, f"0x{lvl:08X}")

    @property
    def feature_names(self) -> list[str]:
        return [n for b, n in FEATURE_BITS.items() if self.features & b]

    def describe(self) -> dict[str, str]:
        return {
            "CCID version": self.version,
            "Slots": str(self.max_slot_index + 1),
            "Voltages": ", ".join(self.voltages) or "none declared",
            "Protocols": ", ".join(self.protocol_names) or "none",
            "Synchronous protocols": ", ".join(self.synchronous_protocols) or "none declared",
            "Default / max clock": f"{self.default_clock_khz} / {self.maximum_clock_khz} kHz",
            "Default / max data rate": f"{self.data_rate_bps} / {self.max_data_rate_bps} bps"
            + (f" ({self.num_data_rates_supported} rates)" if self.num_data_rates_supported else ""),
            "Max IFSD (T=1)": str(self.max_ifsd),
            "Exchange level": self.exchange_level,
            "Features": "; ".join(self.feature_names) or "none",
            "Mechanical": ", ".join(n for b, n in MECHANICAL_BITS.items() if self.mechanical & b) or "none",
            "PIN pad": ", ".join(n for b, n in PIN_BITS.items() if self.pin_support & b) or "none (class 1 reader)",
            "Max CCID message": f"{self.max_ccid_message_length} bytes",
            "GET RESPONSE / ENVELOPE class": f"{self.class_get_response:02X} / {self.class_envelope:02X}",
        }


def parse_class_descriptor(data: bytes) -> CcidDescriptor:
    data = bytes(data)
    if len(data) < CCID_DESCRIPTOR_LENGTH or data[1] != CCID_DESCRIPTOR_TYPE:
        raise ValueError("not a CCID class descriptor (need 54 bytes with bDescriptorType 0x21)")
    (_, _, bcd, slots, volt, protos, dclk, mclk, nclk, drate, mdrate, ndrate, ifsd, sync, mech, feat, maxmsg,
     cls_gr, cls_env, lcd, pin, busy) = struct.unpack("<BBHBBIIIBIIBIIIIIBBHBB", data[:CCID_DESCRIPTOR_LENGTH])
    return CcidDescriptor(data[:CCID_DESCRIPTOR_LENGTH], bcd, slots, volt, protos, dclk, mclk, nclk, drate, mdrate,
                          ndrate, ifsd, sync, mech, feat, maxmsg, cls_gr, cls_env, lcd, pin, busy)


def find_class_descriptor(descriptors: bytes) -> bytes | None:
    """Scan a raw USB descriptor blob (sysfs ``descriptors`` file) for the CCID class descriptor."""
    pos = 0
    while pos + 2 <= len(descriptors):
        length, dtype = descriptors[pos], descriptors[pos + 1]
        if length == 0:
            break
        if dtype == CCID_DESCRIPTOR_TYPE and length == CCID_DESCRIPTOR_LENGTH:
            return descriptors[pos : pos + length]
        pos += length
    return None


@dataclass
class UsbCcidDevice:
    sysfs_path: str
    vendor_id: int
    product_id: int
    manufacturer: str = ""
    product: str = ""
    serial: str = ""
    bcd_device: str = ""
    usb_version: str = ""
    speed_mbps: str = ""
    descriptor: CcidDescriptor | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def is_omnikey(self) -> bool:
        return self.vendor_id == HID_VENDOR_ID

    @property
    def model(self) -> str:
        return OMNIKEY_3x21_PRODUCT_IDS.get(self.product_id, self.product or f"PID {self.product_id:04X}")


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def find_usb_ccid_devices(vendor_id: int | None = None, sysfs_root: str = "/sys/bus/usb/devices") -> list[UsbCcidDevice]:
    """Linux only: enumerate USB devices exposing a CCID interface (no libusb needed)."""
    devices: list[UsbCcidDevice] = []
    for dev in sorted(glob.glob(os.path.join(sysfs_root, "*"))):
        vid_text = _read(os.path.join(dev, "idVendor"))
        if not vid_text:
            continue
        try:
            vid = int(vid_text, 16)
            pid = int(_read(os.path.join(dev, "idProduct")), 16)
        except ValueError:
            continue
        if vendor_id is not None and vid != vendor_id:
            continue
        has_ccid = False
        # interfaces appear both under the device directory and at the bus root (1-2/1-2:1.0 and 1-2:1.0)
        intf_pattern = os.path.basename(dev) + ":*"
        for intf in glob.glob(os.path.join(dev, intf_pattern)) + glob.glob(os.path.join(sysfs_root, intf_pattern)):
            if _read(os.path.join(intf, "bInterfaceClass")).lower() == "0b":
                has_ccid = True
        if not has_ccid:
            continue
        info = UsbCcidDevice(dev, vid, pid, _read(os.path.join(dev, "manufacturer")), _read(os.path.join(dev, "product")),
                             _read(os.path.join(dev, "serial")), _read(os.path.join(dev, "bcdDevice")),
                             _read(os.path.join(dev, "version")), _read(os.path.join(dev, "speed")))
        try:
            with open(os.path.join(dev, "descriptors"), "rb") as fh:
                blob = fh.read()
            cls = find_class_descriptor(blob)
            if cls:
                info.descriptor = parse_class_descriptor(cls)
            else:
                info.warnings.append("CCID class descriptor not found in descriptor blob")
        except OSError as exc:
            info.warnings.append(f"cannot read descriptors: {exc}")
        devices.append(info)
    return devices


# --- PC/SC part 10 GET_TLV_PROPERTIES -----------------------------------------------------
TLV_PROPERTY_NAMES = {
    0x01: "wLcdLayout", 0x02: "bEntryValidationCondition", 0x03: "bTimeOut2", 0x04: "wLcdMaxCharacters",
    0x05: "wLcdMaxLines", 0x06: "bMinPINSize", 0x07: "bMaxPINSize", 0x08: "sFirmwareID", 0x09: "bPPDUSupport",
    0x0A: "dwMaxAPDUDataSize", 0x0B: "wIdVendor", 0x0C: "wIdProduct",
}


def parse_tlv_properties(raw: bytes) -> dict[str, object]:
    out: dict[str, object] = {}
    pos = 0
    while pos + 2 <= len(raw):
        tag, length = raw[pos], raw[pos + 1]
        value = raw[pos + 2 : pos + 2 + length]
        pos += 2 + length
        name = TLV_PROPERTY_NAMES.get(tag, f"tag{tag:02X}")
        if tag == 0x08:
            out[name] = value.decode("ascii", "replace")
        elif tag in (0x0B, 0x0C) and length == 2:
            out[name] = f"{int.from_bytes(value, 'little'):04X}"
        elif length in (1, 2, 4):
            out[name] = int.from_bytes(value, "little")
        else:
            out[name] = value.hex().upper()
    return out
