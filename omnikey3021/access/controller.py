"""Enrol cards and decide access, for both memory cards and ISO 7816 CPU cards."""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from ..atr import CardKind, parse_atr
from ..channel import CardChannel
from ..errors import CardError, CredentialError, OmnikeyError, UnsupportedCardError
from ..iso7816 import Iso7816Card
from ..memorycard import ProtectableMemoryCard, open_memory_card
from .credential import BLOCK_SIZE, Credential, CredentialBlock, FLAG_ACTIVE, derive_card_key
from .store import AccessStore, CardRecord, Holder

log = logging.getLogger(__name__)


@dataclass
class Decision:
    granted: bool
    reason: str
    uid: str | None = None
    credential: Credential | None = None
    holder: Holder | None = None
    card: CardRecord | None = None
    kind: str = ""
    detail: str = ""
    extra: dict = field(default_factory=dict)

    def summary(self) -> str:
        who = self.holder.name if self.holder else "unknown"
        cid = self.credential.card_id if self.credential else "-"
        return f"{'GRANTED' if self.granted else 'DENIED'}: {self.reason} (card {cid}, {who})"


@dataclass
class CardIdentity:
    kind: str
    binding: bytes
    block: bytes

    @property
    def uid(self) -> str:
        return hashlib.sha256(self.kind.encode() + b"|" + self.binding + b"|" + self.block[:32]).hexdigest()[:24]


class AccessController:
    """Reads/writes credential blocks and applies the access policy.

    * Memory cards (SLE 4442/4428/I2C): the block lives at ``mem_offset`` in the
      user area; binding = the first 32 bytes of the card (manufacturer area).
    * ISO 7816 cards: the block lives in transparent EF ``iso_fid`` (optionally
      under application ``iso_aid``); binding = chip serial from GET DATA 9F7F
      when available, else the ATR.  With ``iso_challenge=True`` a GET CHALLENGE /
      INTERNAL AUTHENTICATE round trip with a per-card key is required too.
    """

    def __init__(self, store: AccessStore, site_key: bytes, site_code: int, *, mem_offset: int = 32,
                 iso_fid: int = 0x0001, iso_aid: bytes | None = None, iso_pin: bytes | None = None,
                 iso_challenge: bool = False, memory_kind: str | None = None):
        if len(site_key) < 16:
            raise ValueError("site key must be at least 16 bytes")
        self.store = store
        self.site_key = bytes(site_key)
        self.site_code = site_code
        self.mem_offset = mem_offset
        self.iso_fid = iso_fid
        self.iso_aid = iso_aid
        self.iso_pin = iso_pin
        self.iso_challenge = iso_challenge
        self.memory_kind = memory_kind

    # -- card access -----------------------------------------------------------------------
    def _classify(self, channel: CardChannel) -> CardKind:
        kind = parse_atr(channel.atr).kind
        if self.memory_kind:
            return {"sle4442": CardKind.SLE4442, "sle4428": CardKind.SLE4428, "i2c": CardKind.I2C}[self.memory_kind]
        return kind

    def read_identity(self, channel: CardChannel) -> CardIdentity:
        kind = self._classify(channel)
        if kind in (CardKind.SLE4442, CardKind.SLE4428, CardKind.I2C):
            card = open_memory_card(channel, kind)
            binding = card.read(0, 32)
            block = card.read(self.mem_offset, BLOCK_SIZE)
            return CardIdentity(kind.value, binding, block)
        if kind == CardKind.ASYNC:
            iso = Iso7816Card(channel)
            self._iso_select(iso)
            binding = self._iso_binding(iso, channel)
            block = iso.read_binary(0, BLOCK_SIZE)
            return CardIdentity("iso7816", binding, block)
        raise UnsupportedCardError(f"cannot handle card kind {kind.value}")

    def _iso_select(self, iso: Iso7816Card) -> None:
        if self.iso_aid:
            iso.select_aid(self.iso_aid, return_fci=False)
        else:
            try:
                iso.select_mf()
            except CardError:
                pass
        iso.select_fid(self.iso_fid, p2=0x0C)

    def _iso_binding(self, iso: Iso7816Card, channel: CardChannel) -> bytes:
        try:
            serial = iso.get_data(0x9F7F)
            if serial:
                return b"SN" + serial
        except CardError:
            pass
        return b"ATR" + channel.atr

    def _iso_authenticate(self, iso: Iso7816Card, card_id: int) -> bool:
        """Challenge/response with a per-card key (requires a card applet implementing it)."""
        challenge = hashlib.sha256(str(time.time_ns()).encode() + self.site_key).digest()[:8]
        response = iso.internal_authenticate(challenge)
        serial = self._iso_binding(iso, iso.channel)[2:]
        expected = hmac.new(derive_card_key(self.site_key, card_id), challenge + serial, hashlib.sha256).digest()
        return hmac.compare_digest(expected, response[: len(expected)])

    # -- enrolment -------------------------------------------------------------------------------
    def enroll(self, channel: CardChannel, holder: Holder, *, card_id: int | None = None, expires: float = 0,
               access_level: int | None = None, flags: int = FLAG_ACTIVE, psc: bytes | None = None,
               note: str = "", protect_manufacturer_area: bool = False) -> tuple[Credential, CardRecord]:
        """Write a signed credential to the card and register it."""
        card_id = card_id or self.store.next_card_id()
        level = holder.level if access_level is None else access_level
        cred = Credential(self.site_code, card_id, int(time.time()), int(expires), level, flags)
        kind = self._classify(channel)

        if kind in (CardKind.SLE4442, CardKind.SLE4428, CardKind.I2C):
            card = open_memory_card(channel, kind)
            if isinstance(card, ProtectableMemoryCard) and psc is not None:
                card.verify_psc(psc)
            binding = card.read(0, 32)
            block = CredentialBlock.pack(cred, self.site_key, binding)
            card.write(self.mem_offset, block, verify=True)
            if protect_manufacturer_area and isinstance(card, ProtectableMemoryCard):
                card.protect(0, binding)  # irreversible: freezes the binding
            kind_name = kind.value
        elif kind == CardKind.ASYNC:
            iso = Iso7816Card(channel)
            self._iso_select(iso)
            if self.iso_pin is not None:
                iso.verify(self.iso_pin)
            binding = self._iso_binding(iso, channel)
            block = CredentialBlock.pack(cred, self.site_key, binding)
            iso.update_binary(0, block)
            if iso.read_binary(0, BLOCK_SIZE) != block:
                raise CredentialError("read-back after UPDATE BINARY does not match")
            kind_name = "iso7816"
        else:
            raise UnsupportedCardError(f"cannot enrol card kind {kind.value}")

        ident = CardIdentity(kind_name, binding, block)
        record = self.store.add_card(ident.uid, holder.id, self.site_code, card_id, kind_name, cred.issued,
                                     cred.expires, note)
        self.store.log_event(ident.uid, card_id, holder.name, True, "enrolled", f"level {level}")
        return cred, record

    def erase(self, channel: CardChannel, psc: bytes | None = None) -> None:
        """Overwrite the credential block on the card with zeros."""
        kind = self._classify(channel)
        if kind in (CardKind.SLE4442, CardKind.SLE4428, CardKind.I2C):
            card = open_memory_card(channel, kind)
            if isinstance(card, ProtectableMemoryCard) and psc is not None:
                card.verify_psc(psc)
            card.write(self.mem_offset, b"\x00" * BLOCK_SIZE)
        else:
            iso = Iso7816Card(channel)
            self._iso_select(iso)
            if self.iso_pin is not None:
                iso.verify(self.iso_pin)
            iso.update_binary(0, b"\x00" * BLOCK_SIZE)

    # -- decision ----------------------------------------------------------------------------------
    def check(self, channel: CardChannel, when: float | None = None) -> Decision:
        """Read the card and decide.  Never raises for policy reasons; logs every attempt."""
        try:
            ident = self.read_identity(channel)
        except (OmnikeyError, ValueError) as exc:
            d = Decision(False, "unreadable card", detail=str(exc))
            self.store.log_event(None, None, None, False, d.reason, d.detail)
            return d

        if CredentialBlock.is_blank(ident.block):
            d = Decision(False, "blank card (not enrolled)", uid=ident.uid, kind=ident.kind)
            self.store.log_event(ident.uid, None, None, False, d.reason)
            return d
        try:
            cred = CredentialBlock.parse(ident.block)
        except ValueError as exc:
            d = Decision(False, "invalid credential", uid=ident.uid, kind=ident.kind, detail=str(exc))
            self.store.log_event(ident.uid, None, None, False, d.reason, d.detail)
            return d

        d = Decision(False, "", uid=ident.uid, credential=cred, kind=ident.kind)
        d.card = self.store.get_card(ident.uid)
        d.holder = self.store.get_holder(d.card.holder_id) if d.card and d.card.holder_id else None

        def deny(reason: str, detail: str = "") -> Decision:
            d.granted = False
            d.reason = reason
            d.detail = detail
            self.store.log_event(ident.uid, cred.card_id, d.holder.name if d.holder else None, False, reason, detail)
            return d

        if not CredentialBlock.verify(ident.block, self.site_key, ident.binding):
            return deny("signature invalid (forged, copied to another card, or wrong site key)")
        if cred.site_code != self.site_code:
            return deny(f"wrong site code {cred.site_code}")
        if not cred.flags & FLAG_ACTIVE:
            return deny("credential flagged inactive")
        now = when if when is not None else time.time()
        if cred.expires and now > cred.expires:
            return deny("credential expired")
        if d.card is None:
            return deny("card not in registry")
        if d.card.revoked:
            return deny("card revoked")
        if d.card.card_id != cred.card_id:
            return deny("card id mismatch between card and registry")
        if d.holder is None or not d.holder.active:
            return deny("holder inactive or unknown")
        if not self.store.schedule_allows(cred.access_level, now):
            return deny("outside allowed schedule")
        if ident.kind == "iso7816" and self.iso_challenge:
            try:
                if not self._iso_authenticate(Iso7816Card(channel), cred.card_id):
                    return deny("challenge/response failed")
            except CardError as exc:
                return deny("challenge/response not supported by card", str(exc))

        d.granted = True
        d.reason = "access granted"
        self.store.log_event(ident.uid, cred.card_id, d.holder.name, True, d.reason, f"level {cred.access_level}")
        return d

    # -- monitoring ---------------------------------------------------------------------------------------
    def monitor(self, reader, on_decision: Callable[[Decision], None], *, once: bool = False,
                poll_timeout_s: float | None = None, settle_s: float = 0.2) -> None:
        """Loop: wait for a card, decide, call back, wait for removal.  ``reader`` is an OmnikeyReader."""
        while True:
            reader.wait_for_card(poll_timeout_s)
            time.sleep(settle_s)
            try:
                channel = reader.connect()
            except OmnikeyError as exc:
                on_decision(Decision(False, "could not connect to card", detail=str(exc)))
                reader.wait_for_removal(poll_timeout_s)
                if once:
                    return
                continue
            try:
                decision = self.check(channel)
            finally:
                try:
                    channel.disconnect()
                except OmnikeyError:
                    pass
            on_decision(decision)
            if once:
                return
            reader.wait_for_removal(poll_timeout_s)
