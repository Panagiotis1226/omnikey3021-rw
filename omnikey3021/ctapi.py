"""CT-API (MKT / DIN 66291 "CardTerminal API") for HBCI and other German banking software.

HBCI home-banking applications historically drive the card terminal through
the three CT-API functions ``CT_init``, ``CT_data`` and ``CT_close`` and the
CT-BCS command set (CLA 20: RESET CT, REQUEST ICC, GET STATUS, EJECT ICC ...).
HID ships a CT-API library for OMNIKEY readers; this module offers two things:

* ``PcscCtApi``   - a CT-API implementation on top of PC/SC, so Python HBCI code
  written against CT-API works with the 3021 without any vendor library
* ``NativeCtApi`` - a ctypes wrapper around a vendor CT-API shared library
  (HID's, or any ct-api compliant .dll/.so) with the same Python interface

Addresses: SAD/DAD 0 = ICC1, 1 = CT (the terminal itself), 2 = HOST.
Return codes: 0 OK, -1 ERR_INVALID, -8 ERR_CT, -10 ERR_TRANS, -11 ERR_MEMORY,
-127 ERR_HTSI, -128 ERR_HOST.
"""

from __future__ import annotations

import ctypes

from . import pcsc_constants as C
from .errors import NoCardError, OmnikeyError, PCSCError

OK = 0
ERR_INVALID = -1
ERR_CT = -8
ERR_TRANS = -10
ERR_MEMORY = -11
ERR_HTSI = -127
ERR_HOST = -128
RETURN_CODE_NAMES = {0: "OK", -1: "ERR_INVALID", -8: "ERR_CT", -10: "ERR_TRANS", -11: "ERR_MEMORY",
                     -127: "ERR_HTSI", -128: "ERR_HOST"}

ICC1 = 0x00
CT = 0x01
HOST = 0x02

CLA_CT = 0x20
INS_RESET_CT = 0x11
INS_REQUEST_ICC = 0x12
INS_GET_STATUS = 0x13
INS_EJECT_ICC = 0x15
INS_INPUT = 0x16
INS_OUTPUT = 0x17
INS_PERFORM_VERIFICATION = 0x18
INS_MODIFY_VERIFICATION = 0x19

CT_MANUFACTURER = b"HID  OMNIKEY 3021  1.00"  # 5 chars manufacturer, 10 chars type, 5 chars version (CT-BCS)


class PcscCtApi:
    """CT-API semantics implemented with the PC/SC binding (one terminal = one reader)."""

    def __init__(self, reader_name: str | None = None, pattern: str | None = None, reader_factory=None):
        self.reader_name = reader_name
        self.pattern = pattern
        self.reader_factory = reader_factory  # callable(pn) -> reader-like object (used for simulation/tests)
        self._terminals: dict[int, dict] = {}

    # -- CT-API --------------------------------------------------------------------------
    def CT_init(self, ctn: int, pn: int) -> int:
        """Open terminal number ``ctn`` on port ``pn`` (pn = index into the OMNIKEY reader list)."""
        if ctn in self._terminals:
            return ERR_INVALID
        if self.reader_factory is not None:
            try:
                reader = self.reader_factory(pn)
            except Exception:  # noqa: BLE001
                return ERR_CT
            self._terminals[ctn] = {"reader": reader, "session": None}
            return OK
        try:
            from .reader import OmnikeyReader

            names = OmnikeyReader.list(self.pattern)
            name = self.reader_name or (names[pn] if pn < len(names) else None)
            if name is None:
                return ERR_CT
            reader = OmnikeyReader(name)
        except (OmnikeyError, IndexError):
            return ERR_CT
        self._terminals[ctn] = {"reader": reader, "session": None}
        return OK

    def CT_close(self, ctn: int) -> int:
        term = self._terminals.pop(ctn, None)
        if term is None:
            return ERR_INVALID
        if term["session"] is not None:
            try:
                term["session"].disconnect(C.SCARD_UNPOWER_CARD)
            except OmnikeyError:
                pass
        term["reader"].close()
        return OK

    def CT_data(self, ctn: int, dad: int, sad: int, command: bytes) -> tuple[int, int, int, bytes]:
        """Returns (rc, dad, sad, response) - response includes SW1 SW2; dad/sad are swapped like the C API."""
        term = self._terminals.get(ctn)
        if term is None or sad != HOST:
            return ERR_INVALID, dad, sad, b""
        command = bytes(command)
        try:
            if dad == CT:
                resp = self._ct_bcs(term, command)
            elif dad == ICC1:
                resp = self._icc(term, command)
            else:
                return ERR_INVALID, dad, sad, b""
        except NoCardError:
            return ERR_TRANS, HOST, dad, b""
        except PCSCError:
            return ERR_CT, HOST, dad, b""
        return OK, HOST, dad, resp

    # -- helpers -----------------------------------------------------------------------------
    def _connect(self, term: dict, wait_s: float | None = None) -> None:
        if term["session"] is not None:
            try:
                if hasattr(term["session"], "status"):
                    term["session"].status()
                return
            except OmnikeyError:
                term["session"] = None
        reader = term["reader"]
        if wait_s is not None:
            reader.wait_for_card(wait_s)
        term["session"] = reader.connect()

    def _icc(self, term: dict, command: bytes) -> bytes:
        self._connect(term)
        return term["session"].transmit(command)

    def _ct_bcs(self, term: dict, cmd: bytes) -> bytes:
        if len(cmd) < 4 or cmd[0] != CLA_CT:
            return b"\x6e\x00"
        ins, p1, p2 = cmd[1], cmd[2], cmd[3]
        data = cmd[5 : 5 + cmd[4]] if len(cmd) > 5 else b""
        reader = term["reader"]

        if ins == INS_RESET_CT:
            if p1 == 0x00:  # reset the terminal
                if term["session"] is not None:
                    try:
                        term["session"].disconnect(C.SCARD_UNPOWER_CARD)
                    except OmnikeyError:
                        pass
                    term["session"] = None
                return b"\x90\x00"
            if p1 in (0x01, 0x02):  # reset ICC (warm/cold)
                if not reader.is_card_present():
                    return b"\x64\x00"  # ICC not present / not activated
                if term["session"] is None:
                    self._connect(term)
                else:
                    term["session"].reconnect(True)
                atr = term["session"].atr
                sw = b"\x90\x01"  # asynchronous ICC
                from .atr import parse_atr

                parsed = parse_atr(atr)
                if parsed.is_memory_card:
                    sw = b"\x90\x00"  # synchronous ICC
                if p2 == 0x01:
                    return atr + sw
                if p2 == 0x02:
                    return parsed.historical + sw
                return sw
            return b"\x6a\x00"

        if ins == INS_REQUEST_ICC:
            if p1 != 0x01:
                return b"\x6a\x00"
            timeout = data[0] if data else None
            if not reader.is_card_present():
                try:
                    reader.wait_for_card(float(timeout) if timeout else None)
                except PCSCError:
                    return b"\x62\x00"  # no card presented within timeout
            try:
                self._connect(term)
            except NoCardError:
                return b"\x62\x00"
            atr = term["session"].atr
            from .atr import parse_atr

            parsed = parse_atr(atr)
            sw = b"\x90\x00" if parsed.is_memory_card else b"\x90\x01"
            if p2 == 0x01:
                return atr + sw
            if p2 == 0x02:
                return parsed.historical + sw
            return sw

        if ins == INS_GET_STATUS:
            if p2 == 0x46:  # CT manufacturer data
                return b"\x46" + bytes([len(CT_MANUFACTURER)]) + CT_MANUFACTURER + b"\x90\x00"
            if p2 == 0x80:  # ICC status
                if not reader.is_card_present():
                    status = 0x00
                elif term["session"] is None:
                    status = 0x03  # ICC present, not connected
                else:
                    status = 0x05  # ICC present and connected
                return b"\x80\x01" + bytes([status]) + b"\x90\x00"
            return b"\x6a\x00"

        if ins == INS_EJECT_ICC:
            if term["session"] is not None:
                try:
                    term["session"].disconnect(C.SCARD_UNPOWER_CARD)
                except OmnikeyError:
                    pass
                term["session"] = None
            if p2 & 0x04 and data:  # wait for removal with timeout
                try:
                    reader.wait_for_removal(float(data[0]))
                except PCSCError:
                    return b"\x62\x00"
            return b"\x90\x00"

        if ins in (INS_PERFORM_VERIFICATION, INS_MODIFY_VERIFICATION, INS_INPUT, INS_OUTPUT):
            return b"\x6d\x00"  # class 1 terminal: no keypad / display
        return b"\x6d\x00"


class NativeCtApi:
    """ctypes wrapper for a vendor CT-API library (e.g. HID's ct-api for OMNIKEY, or libctapi*.so)."""

    def __init__(self, library_path: str):
        self.lib = ctypes.CDLL(library_path)
        u8p = ctypes.POINTER(ctypes.c_ubyte)
        self.lib.CT_init.restype = ctypes.c_int8
        self.lib.CT_init.argtypes = [ctypes.c_uint16, ctypes.c_uint16]
        self.lib.CT_close.restype = ctypes.c_int8
        self.lib.CT_close.argtypes = [ctypes.c_uint16]
        self.lib.CT_data.restype = ctypes.c_int8
        self.lib.CT_data.argtypes = [ctypes.c_uint16, u8p, u8p, ctypes.c_uint16, u8p, ctypes.POINTER(ctypes.c_uint16), u8p]

    def CT_init(self, ctn: int, pn: int) -> int:
        return int(self.lib.CT_init(ctn, pn))

    def CT_close(self, ctn: int) -> int:
        return int(self.lib.CT_close(ctn))

    def CT_data(self, ctn: int, dad: int, sad: int, command: bytes) -> tuple[int, int, int, bytes]:
        cmd = (ctypes.c_ubyte * len(command))(*command)
        resp = (ctypes.c_ubyte * 65538)()
        lenr = ctypes.c_uint16(65538)
        d, s = ctypes.c_ubyte(dad), ctypes.c_ubyte(sad)
        rc = int(self.lib.CT_data(ctn, ctypes.byref(d), ctypes.byref(s), len(command), cmd, ctypes.byref(lenr), resp))
        return rc, d.value, s.value, bytes(resp[: lenr.value])


def ct_bcs(ins: int, p1: int, p2: int, data: bytes = b"", le: int | None = None) -> bytes:
    """Build a CT-BCS command APDU (CLA 20)."""
    out = bytes([CLA_CT, ins, p1, p2])
    if data:
        out += bytes([len(data)]) + bytes(data)
    if le is not None:
        out += bytes([le])
    return out


def request_icc_and_reset(api, ctn: int = 1, pn: int = 0, timeout_s: int = 30) -> bytes:
    """Convenience: CT_init, REQUEST ICC (wait), RESET ICC with ATR; returns the ATR."""
    rc = api.CT_init(ctn, pn)
    if rc != OK:
        raise OmnikeyError(f"CT_init failed: {RETURN_CODE_NAMES.get(rc, rc)}")
    rc, _, _, resp = api.CT_data(ctn, CT, HOST, ct_bcs(INS_REQUEST_ICC, 0x01, 0x01, bytes([timeout_s & 0xFF]), 0x00))
    if rc != OK or resp[-2:] not in (b"\x90\x00", b"\x90\x01"):
        raise OmnikeyError(f"REQUEST ICC failed: rc={rc} sw={resp[-2:].hex()}")
    return resp[:-2]


__all__ = ["PcscCtApi", "NativeCtApi", "ct_bcs", "request_icc_and_reset", "OK", "ERR_INVALID", "ERR_CT", "ERR_TRANS",
           "ERR_MEMORY", "ERR_HTSI", "ERR_HOST", "ICC1", "CT", "HOST"]
