"""omnikey3021 - read/write toolkit for the HID OMNIKEY 3021 contact smart card reader.

Layers (bottom up):

* ``pcsc``        ctypes binding to winscard / pcsc-lite (no third-party packages)
* ``reader``      OmnikeyReader / CardSession: discovery, card events, transmit, control
* ``atr``         ISO 7816-3 ATR parsing and memory-card recognition
* ``apdu``        APDU encoding (short + extended), status words, T=0 conveniences
* ``iso7816``     ISO 7816-4 commands for CPU cards (T=0 / T=1)
* ``memorycard``  SLE 4442/4432, SLE 4428/4418 and I2C cards via the OMNIKEY CLA=FF command set
* ``vendor``      OMNIKEY vendor API: reader capabilities, slot configuration, user EEPROM, raw bus commands
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
from .iso7816 import FCI, Iso7816Card
from .memorycard import I2CCard, MemoryCard, SLE4428Card, SLE4442Card, open_memory_card
from .vendor import ReaderConfig

__version__ = "1.0.0"

__all__ = [
    "CommandAPDU", "ResponseAPDU", "describe_sw", "transmit_apdu",
    "ATR", "CardKind", "parse_atr",
    "CardError", "CredentialError", "NoCardError", "OmnikeyError", "PCSCError", "ReaderNotFoundError",
    "UnsupportedCardError", "VendorError",
    "FCI", "Iso7816Card",
    "I2CCard", "MemoryCard", "SLE4428Card", "SLE4442Card", "open_memory_card",
    "ReaderConfig",
    "OmnikeyReader", "CardSession",
]


def __getattr__(name):
    # OmnikeyReader needs the PC/SC library; import lazily so the pure parts work without it.
    if name in ("OmnikeyReader", "CardSession"):
        from . import reader

        return getattr(reader, name)
    raise AttributeError(name)
