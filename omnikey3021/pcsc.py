"""Minimal, dependency-free PC/SC binding built on ctypes.

Works with:

* Windows  - ``winscard.dll`` (Microsoft Smart Card Resource Manager)
* macOS    - ``PCSC.framework``
* Linux    - ``libpcsclite.so.1`` (pcsc-lite)

Only the calls the toolkit needs are wrapped, but they are wrapped completely
(readers, connect/reconnect, transmit, control, status, status change, attributes,
transactions).  The type sizes differ per platform and are handled here so the
rest of the package is platform agnostic.
"""

from __future__ import annotations

import ctypes
import ctypes.util
from ctypes import POINTER, Structure, byref, c_char_p, c_void_p, create_string_buffer
from dataclasses import dataclass
from typing import Iterable, Sequence

from . import pcsc_constants as C
from .errors import NoCardError, PCSCError, ReaderNotFoundError

# ---------------------------------------------------------------------------
# Platform specific types
# ---------------------------------------------------------------------------
if C.IS_WINDOWS:
    DWORD = ctypes.c_uint32
    LONG = ctypes.c_int32
    SCARDCONTEXT = ctypes.c_size_t  # ULONG_PTR
    SCARDHANDLE = ctypes.c_size_t
    _STRUCT_PACK = None
    _SUFFIX = "A"
elif C.IS_MACOS:
    DWORD = ctypes.c_uint32
    LONG = ctypes.c_int32
    SCARDCONTEXT = ctypes.c_int32
    SCARDHANDLE = ctypes.c_int32
    _STRUCT_PACK = 1
    _SUFFIX = ""
else:
    DWORD = ctypes.c_ulong
    LONG = ctypes.c_long
    SCARDCONTEXT = ctypes.c_long
    SCARDHANDLE = ctypes.c_long
    _STRUCT_PACK = None
    _SUFFIX = ""

LPDWORD = POINTER(DWORD)


class SCARD_IO_REQUEST(Structure):
    if _STRUCT_PACK:
        _pack_ = _STRUCT_PACK
    _fields_ = [("dwProtocol", DWORD), ("cbPciLength", DWORD)]


class SCARD_READERSTATE(Structure):
    if _STRUCT_PACK:
        _pack_ = _STRUCT_PACK
    _fields_ = [
        ("szReader", c_char_p),
        ("pvUserData", c_void_p),
        ("dwCurrentState", DWORD),
        ("dwEventState", DWORD),
        ("cbAtr", DWORD),
        ("rgbAtr", ctypes.c_ubyte * C.MAX_ATR_SIZE),
    ]


# ---------------------------------------------------------------------------
# Library loading (lazy, so importing the package never requires PC/SC)
# ---------------------------------------------------------------------------
_lib = None


def _load_library():
    global _lib
    if _lib is not None:
        return _lib
    if C.IS_WINDOWS:
        lib = ctypes.WinDLL("winscard.dll")
    elif C.IS_MACOS:
        lib = ctypes.CDLL("/System/Library/Frameworks/PCSC.framework/PCSC")
    else:
        name = ctypes.util.find_library("pcsclite") or "libpcsclite.so.1"
        try:
            lib = ctypes.CDLL(name)
        except OSError as exc:  # pragma: no cover - depends on host
            raise PCSCError(
                C.SCARD_E_NO_SERVICE,
                "load",
                "libpcsclite not found. Install pcsc-lite (e.g. `apt install pcscd libpcsclite1`).",
            ) from exc

    def fn(name, restype, argtypes, suffix=_SUFFIX):
        f = getattr(lib, name + suffix) if hasattr(lib, name + suffix) else getattr(lib, name)
        f.restype = restype
        f.argtypes = argtypes
        return f

    lib._EstablishContext = fn("SCardEstablishContext", LONG, [DWORD, c_void_p, c_void_p, POINTER(SCARDCONTEXT)], "")
    lib._ReleaseContext = fn("SCardReleaseContext", LONG, [SCARDCONTEXT], "")
    lib._IsValidContext = fn("SCardIsValidContext", LONG, [SCARDCONTEXT], "")
    lib._ListReaders = fn("SCardListReaders", LONG, [SCARDCONTEXT, c_char_p, c_char_p, LPDWORD])
    lib._Connect = fn("SCardConnect", LONG, [SCARDCONTEXT, c_char_p, DWORD, DWORD, POINTER(SCARDHANDLE), LPDWORD])
    lib._Reconnect = fn("SCardReconnect", LONG, [SCARDHANDLE, DWORD, DWORD, DWORD, LPDWORD], "")
    lib._Disconnect = fn("SCardDisconnect", LONG, [SCARDHANDLE, DWORD], "")
    lib._BeginTransaction = fn("SCardBeginTransaction", LONG, [SCARDHANDLE], "")
    lib._EndTransaction = fn("SCardEndTransaction", LONG, [SCARDHANDLE, DWORD], "")
    lib._Status = fn("SCardStatus", LONG, [SCARDHANDLE, c_char_p, LPDWORD, LPDWORD, LPDWORD, c_void_p, LPDWORD])
    lib._GetStatusChange = fn("SCardGetStatusChange", LONG, [SCARDCONTEXT, DWORD, POINTER(SCARD_READERSTATE), DWORD])
    lib._Cancel = fn("SCardCancel", LONG, [SCARDCONTEXT], "")
    lib._Transmit = fn(
        "SCardTransmit",
        LONG,
        [SCARDHANDLE, POINTER(SCARD_IO_REQUEST), c_void_p, DWORD, POINTER(SCARD_IO_REQUEST), c_void_p, LPDWORD],
        "",
    )
    lib._Control = fn("SCardControl", LONG, [SCARDHANDLE, DWORD, c_void_p, DWORD, c_void_p, DWORD, LPDWORD], "")
    lib._GetAttrib = fn("SCardGetAttrib", LONG, [SCARDHANDLE, DWORD, c_void_p, LPDWORD], "")
    lib._SetAttrib = fn("SCardSetAttrib", LONG, [SCARDHANDLE, DWORD, c_void_p, DWORD], "")
    _lib = lib
    return lib


def _check(rv: int, function: str) -> None:
    rv &= 0xFFFFFFFF
    if rv == C.SCARD_S_SUCCESS:
        return
    if rv in (C.SCARD_E_NO_SMARTCARD, C.SCARD_W_REMOVED_CARD):
        raise NoCardError(f"{function}: no card in reader ({C.ERROR_NAMES.get(rv)})")
    if rv == C.SCARD_W_UNRESPONSIVE_CARD:
        raise NoCardError(f"{function}: card is mute / unresponsive (SCARD_W_UNRESPONSIVE_CARD)")
    if rv == C.SCARD_E_UNKNOWN_READER:
        raise ReaderNotFoundError(f"{function}: unknown reader (SCARD_E_UNKNOWN_READER)")
    raise PCSCError(rv, function)


def _pci(protocol: int) -> SCARD_IO_REQUEST:
    return SCARD_IO_REQUEST(protocol, ctypes.sizeof(SCARD_IO_REQUEST))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
@dataclass
class ReaderState:
    reader: str
    event_state: int
    atr: bytes

    @property
    def present(self) -> bool:
        return bool(self.event_state & C.SCARD_STATE_PRESENT)

    @property
    def changed(self) -> bool:
        return bool(self.event_state & C.SCARD_STATE_CHANGED)

    @property
    def in_use(self) -> bool:
        return bool(self.event_state & (C.SCARD_STATE_INUSE | C.SCARD_STATE_EXCLUSIVE))

    @property
    def mute(self) -> bool:
        return bool(self.event_state & C.SCARD_STATE_MUTE)


@dataclass
class CardStatus:
    reader: str
    state: int
    protocol: int
    atr: bytes

    @property
    def present(self) -> bool:
        return bool(self.state & (C.SCARD_PRESENT | C.SCARD_POWERED | C.SCARD_NEGOTIABLE | C.SCARD_SPECIFIC))


class Context:
    """A PC/SC resource-manager context (SCardEstablishContext)."""

    def __init__(self, scope: int = C.SCARD_SCOPE_USER):
        self._lib = _load_library()
        self._ctx = SCARDCONTEXT()
        _check(self._lib._EstablishContext(scope, None, None, byref(self._ctx)), "SCardEstablishContext")

    # -- lifecycle ---------------------------------------------------------
    def release(self) -> None:
        if self._ctx.value:
            self._lib._ReleaseContext(self._ctx)
            self._ctx = SCARDCONTEXT()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.release()

    def is_valid(self) -> bool:
        return (self._lib._IsValidContext(self._ctx) & 0xFFFFFFFF) == C.SCARD_S_SUCCESS

    def cancel(self) -> None:
        """Abort a blocking SCardGetStatusChange in another thread."""
        self._lib._Cancel(self._ctx)

    # -- readers -----------------------------------------------------------
    def list_readers(self) -> list[str]:
        length = DWORD(0)
        rv = self._lib._ListReaders(self._ctx, None, None, byref(length)) & 0xFFFFFFFF
        if rv == C.SCARD_E_NO_READERS_AVAILABLE:
            return []
        _check(rv, "SCardListReaders")
        buf = create_string_buffer(length.value)
        rv = self._lib._ListReaders(self._ctx, None, buf, byref(length)) & 0xFFFFFFFF
        if rv == C.SCARD_E_NO_READERS_AVAILABLE:
            return []
        _check(rv, "SCardListReaders")
        raw = buf.raw[: length.value]
        return [r.decode("utf-8", "replace") for r in raw.split(b"\x00") if r]

    def get_status_change(self, readers: Sequence[str], current_states: Sequence[int] | None = None,
                          timeout_ms: int = C.INFINITE) -> list[ReaderState]:
        """Wrap SCardGetStatusChange for the given readers.

        Pass ``current_states`` from a previous call to block until something
        changes; pass ``SCARD_STATE_UNAWARE`` (default) to get the present state
        immediately.
        """
        n = len(readers)
        if n == 0:
            return []
        states = (SCARD_READERSTATE * n)()
        encoded = [r.encode("utf-8") for r in readers]
        for i, name in enumerate(encoded):
            states[i].szReader = name
            states[i].dwCurrentState = current_states[i] if current_states else C.SCARD_STATE_UNAWARE
        rv = self._lib._GetStatusChange(self._ctx, timeout_ms & 0xFFFFFFFF, states, n) & 0xFFFFFFFF
        if rv == C.SCARD_E_TIMEOUT:
            # Return the (unchanged) states so callers can loop.
            pass
        elif rv == C.SCARD_E_CANCELLED:
            raise PCSCError(rv, "SCardGetStatusChange")
        else:
            _check(rv, "SCardGetStatusChange")
        out = []
        for i, r in enumerate(readers):
            st = states[i]
            out.append(ReaderState(r, int(st.dwEventState), bytes(st.rgbAtr[: st.cbAtr])))
        return out

    def wait_for_card(self, reader: str, timeout_ms: int = C.INFINITE) -> ReaderState:
        """Block until a card is present in ``reader`` (or timeout)."""
        state = self.get_status_change([reader], None, 0)[0]
        cur = state.event_state
        while not state.present:
            state = self.get_status_change([reader], [cur], timeout_ms)[0]
            if not state.changed and not state.present:
                raise PCSCError(C.SCARD_E_TIMEOUT, "wait_for_card")
            cur = state.event_state & ~C.SCARD_STATE_CHANGED
        return state

    def wait_for_removal(self, reader: str, timeout_ms: int = C.INFINITE) -> ReaderState:
        state = self.get_status_change([reader], None, 0)[0]
        cur = state.event_state
        while state.present:
            state = self.get_status_change([reader], [cur], timeout_ms)[0]
            if not state.changed and state.present:
                raise PCSCError(C.SCARD_E_TIMEOUT, "wait_for_removal")
            cur = state.event_state & ~C.SCARD_STATE_CHANGED
        return state

    # -- connection ----------------------------------------------------------
    def connect(self, reader: str, share_mode: int = C.SCARD_SHARE_SHARED,
                protocols: int = C.SCARD_PROTOCOL_ANY) -> "Card":
        handle = SCARDHANDLE()
        active = DWORD(0)
        if share_mode == C.SCARD_SHARE_DIRECT:
            protocols = C.SCARD_PROTOCOL_UNDEFINED
        _check(self._lib._Connect(self._ctx, reader.encode("utf-8"), share_mode, protocols,
                                  byref(handle), byref(active)), "SCardConnect")
        return Card(self, handle, reader, int(active.value))


class Card:
    """A connected card handle (SCardConnect)."""

    def __init__(self, context: Context, handle, reader: str, protocol: int):
        self._lib = context._lib
        self.context = context
        self._handle = handle
        self.reader = reader
        self.protocol = protocol
        self._atr: bytes | None = None

    # -- lifecycle -----------------------------------------------------------
    def disconnect(self, disposition: int = C.SCARD_LEAVE_CARD) -> None:
        if self._handle is not None:
            self._lib._Disconnect(self._handle, disposition)
            self._handle = None

    def reconnect(self, share_mode: int = C.SCARD_SHARE_SHARED, protocols: int = C.SCARD_PROTOCOL_ANY,
                  initialization: int = C.SCARD_RESET_CARD) -> int:
        active = DWORD(0)
        _check(self._lib._Reconnect(self._handle, share_mode, protocols, initialization, byref(active)),
               "SCardReconnect")
        self.protocol = int(active.value)
        self._atr = None
        return self.protocol

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.disconnect()

    def begin_transaction(self) -> None:
        _check(self._lib._BeginTransaction(self._handle), "SCardBeginTransaction")

    def end_transaction(self, disposition: int = C.SCARD_LEAVE_CARD) -> None:
        _check(self._lib._EndTransaction(self._handle, disposition), "SCardEndTransaction")

    # -- information ---------------------------------------------------------
    def status(self) -> CardStatus:
        name_len = DWORD(0)
        state = DWORD(0)
        proto = DWORD(0)
        atr = (ctypes.c_ubyte * C.MAX_ATR_SIZE)()
        atr_len = DWORD(C.MAX_ATR_SIZE)
        # First call: get reader name length.
        rv = self._lib._Status(self._handle, None, byref(name_len), byref(state), byref(proto), atr, byref(atr_len))
        rv &= 0xFFFFFFFF
        name = self.reader
        if rv == C.SCARD_E_INSUFFICIENT_BUFFER or (rv == C.SCARD_S_SUCCESS and name_len.value):
            buf = create_string_buffer(max(name_len.value, 1))
            atr_len = DWORD(C.MAX_ATR_SIZE)
            rv = self._lib._Status(self._handle, buf, byref(name_len), byref(state), byref(proto), atr,
                                   byref(atr_len)) & 0xFFFFFFFF
            if rv == C.SCARD_S_SUCCESS:
                name = buf.raw.split(b"\x00")[0].decode("utf-8", "replace") or self.reader
        _check(rv, "SCardStatus")
        self.protocol = int(proto.value) or self.protocol
        self._atr = bytes(atr[: atr_len.value])
        return CardStatus(name, int(state.value), int(proto.value), self._atr)

    @property
    def atr(self) -> bytes:
        if self._atr is None:
            try:
                self.status()
            except PCSCError:
                self._atr = b""
        return self._atr or b""

    def get_attrib(self, attr: int) -> bytes:
        length = DWORD(0)
        rv = self._lib._GetAttrib(self._handle, attr, None, byref(length)) & 0xFFFFFFFF
        if rv == C.SCARD_E_INSUFFICIENT_BUFFER or (rv == C.SCARD_S_SUCCESS and length.value == 0):
            length = DWORD(max(length.value, 256))
        _check(rv, "SCardGetAttrib")
        buf = create_string_buffer(length.value)
        _check(self._lib._GetAttrib(self._handle, attr, buf, byref(length)), "SCardGetAttrib")
        return buf.raw[: length.value]

    def set_attrib(self, attr: int, value: bytes) -> None:
        buf = create_string_buffer(bytes(value), len(value))
        _check(self._lib._SetAttrib(self._handle, attr, buf, len(value)), "SCardSetAttrib")

    # -- I/O -------------------------------------------------------------------
    def transmit(self, data: bytes, recv_size: int = C.MAX_BUFFER_SIZE_EXTENDED) -> bytes:
        send = create_string_buffer(bytes(data), len(data))
        recv = create_string_buffer(recv_size)
        recv_len = DWORD(recv_size)
        send_pci = _pci(self.protocol if self.protocol else C.SCARD_PROTOCOL_T0)
        recv_pci = _pci(self.protocol if self.protocol else C.SCARD_PROTOCOL_T0)
        _check(self._lib._Transmit(self._handle, byref(send_pci), send, len(data), byref(recv_pci),
                                   recv, byref(recv_len)), "SCardTransmit")
        return recv.raw[: recv_len.value]

    def control(self, code: int, data: bytes = b"", recv_size: int = 4096) -> bytes:
        send = create_string_buffer(bytes(data), len(data)) if data else None
        recv = create_string_buffer(recv_size)
        returned = DWORD(0)
        _check(self._lib._Control(self._handle, code, send, len(data), recv, recv_size, byref(returned)),
               "SCardControl")
        return recv.raw[: returned.value]


def list_readers(scope: int = C.SCARD_SCOPE_USER) -> list[str]:
    """Convenience: list all PC/SC readers on this machine."""
    with Context(scope) as ctx:
        return ctx.list_readers()


def find_omnikey_readers(readers: Iterable[str], pattern: str | None = None) -> list[str]:
    """Filter reader names for OMNIKEY 3021 / 3x21 devices.

    The CCID driver names the device "HID Global OMNIKEY 3x21 Smart Card Reader"
    (Linux/macOS libccid) or "HID Global OMNIKEY Smart Card Reader 0" (Windows,
    per the HID developer guide); the legacy HID driver used "OMNIKEY CardMan
    3x21".  A custom substring can be supplied.
    """
    pat = (pattern or "omnikey").lower()
    return [r for r in readers if pat in r.lower()]
