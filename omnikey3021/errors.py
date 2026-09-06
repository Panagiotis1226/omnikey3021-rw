"""Exception hierarchy for the OMNIKEY 3021 toolkit."""

from __future__ import annotations


class OmnikeyError(Exception):
    """Base class for all errors raised by this package."""


class ReaderNotFoundError(OmnikeyError):
    """No matching PC/SC reader is connected."""


class NoCardError(OmnikeyError):
    """The reader slot is empty (or the card is mute / unpowered)."""


class PCSCError(OmnikeyError):
    """A PC/SC (winscard / pcsc-lite) call returned an error code."""

    def __init__(self, code: int, function: str = "", message: str | None = None):
        from .pcsc_constants import ERROR_NAMES  # local import avoids cycles

        self.code = code & 0xFFFFFFFF
        self.function = function
        self.name = ERROR_NAMES.get(self.code, "UNKNOWN_ERROR")
        text = message or f"{function or 'PC/SC'} failed: {self.name} (0x{self.code:08X})"
        if self.code == 0x8010001D and not message:
            text += " - the PC/SC service is not running (Linux: `sudo systemctl start pcscd`; Windows: Smart Card service)"
        elif self.code == 0x8010002E and not message:
            text += " - no reader connected"
        super().__init__(text)


class CardError(OmnikeyError):
    """The card (or the reader emulating one) answered with a non-success status word."""

    def __init__(self, sw1: int, sw2: int, description: str = "", command: bytes | None = None):
        from .apdu import describe_sw

        self.sw1 = sw1
        self.sw2 = sw2
        self.sw = (sw1 << 8) | sw2
        self.description = description or describe_sw(sw1, sw2)
        self.command = command
        text = f"SW {self.sw:04X}: {self.description}"
        if command is not None:
            text += f" (command {command.hex().upper()})"
        super().__init__(text)


class VendorError(OmnikeyError):
    """The reader firmware returned an error response TLV (tag 9E) to a vendor command."""

    def __init__(self, cycle: int, code: int):
        from .vendor import ERROR_CYCLES, ERROR_CODES

        self.cycle = cycle
        self.code = code
        super().__init__(
            f"reader firmware error: {ERROR_CODES.get(code, 'UNKNOWN')} (0x{code:02X}) "
            f"during {ERROR_CYCLES.get(cycle, 'RFU')} (cycle {cycle})"
        )


class UnsupportedCardError(OmnikeyError):
    """The inserted card is not of the type the operation requires."""


class CredentialError(OmnikeyError):
    """A credential block on a card is missing, malformed, or fails authentication."""
