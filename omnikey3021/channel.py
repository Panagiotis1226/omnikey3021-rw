"""Transport abstraction shared by the real reader and the simulator."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class CardChannel(Protocol):
    """Anything that can exchange raw APDUs with a card and control codes with a reader."""

    @property
    def atr(self) -> bytes: ...

    @property
    def protocol(self) -> int: ...

    def transmit(self, data: bytes) -> bytes: ...

    def control(self, code: int, data: bytes = b"") -> bytes: ...
