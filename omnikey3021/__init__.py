"""omnikey3021 - read/write toolkit for the HID OMNIKEY 3021 contact smart card reader.

Layers (bottom up):

* ``pcsc``        ctypes binding to winscard / pcsc-lite (no third-party packages)
* ``reader``      OmnikeyReader / CardSession: discovery, card events, transmit, control
* ``atr``         ISO 7816-3 ATR parsing and memory-card recognition
* ``apdu``        APDU encoding (short + extended), status words, T=0 conveniences
* ``iso7816``     ISO 7816-4 commands for CPU cards (T=0 / T=1)
* ``memorycard``  SLE 4442/4432, SLE 4428/4418 and I2C cards via the OMNIKEY CLA=FF command set
* ``vendor``      OMNIKEY vendor API: reader capabilities, slot configuration, user EEPROM, raw bus commands
* ``emv``         EMV payment cards (read-only Level 2) and EMV Book 1 ATR checks
* ``ccid``        USB CCID class descriptor and PC/SC part 10 properties
* ``hbci``        HBCI/FinTS DDV banking cards
* ``calypso``     Calypso transport cards (read + secure-session read/write with a SAM)
* ``ctapi``       CT-API (MKT) interface over PC/SC or a vendor library
* ``access``      credential format, SQLite registry and access decisions for door control
* ``simulator``   hardware-free reader/card simulation
"""

from .apdu import CommandAPDU, ResponseAPDU, describe_sw, transmit_apdu
from .atr import ATR, CardKind, parse_atr
from .errors import (
    CardError,
    CredentialError,
    NoCardError,
    OmnikeyError,
    PCSCError,
    ReaderNotFoundError,
    UnsupportedCardError,
    VendorError,
)
from .emv import EmvCard, TerminalData
from .hbci import DDVCard
from .calypso import CalypsoCard, PcscSam
from .iso7816 import FCI, Iso7816Card, Iso7816CardExtended
from .memorycard import I2CCard, MemoryCard, SLE4428Card, SLE4442Card, open_memory_card
from .vendor import ReaderConfig

__version__ = "1.0.3"

__all__ = [
    "CommandAPDU", "ResponseAPDU", "describe_sw", "transmit_apdu",
    "ATR", "CardKind", "parse_atr",
    "CardError", "CredentialError", "NoCardError", "OmnikeyError", "PCSCError", "ReaderNotFoundError",
    "UnsupportedCardError", "VendorError",
    "FCI", "Iso7816Card", "Iso7816CardExtended", "EmvCard", "TerminalData", "DDVCard", "CalypsoCard", "PcscSam",
    "I2CCard", "MemoryCard", "SLE4428Card", "SLE4442Card", "open_memory_card",
    "ReaderConfig",
    "OmnikeyReader", "CardSession", "CardMonitor", "PcscCtApi",
]


def __getattr__(name):
    # OmnikeyReader needs the PC/SC library; import lazily so the pure parts work without it.
    if name in ("OmnikeyReader", "CardSession"):
        from . import reader

        return getattr(reader, name)
    if name == "CardMonitor":
        from .pcsc import CardMonitor

        return CardMonitor
    if name == "PcscCtApi":
        from .ctapi import PcscCtApi

        return PcscCtApi
    raise AttributeError(name)
