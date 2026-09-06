"""HBCI / FinTS chip-card support (DDV procedure, ZKA "Bankensignaturkarte").

The OMNIKEY 3021 is listed as HBCI compatible: it is a *class 1* card terminal
(no keypad, no display) that home-banking software uses through CT-API or
PC/SC to talk to the customer's DDV chip card.  This module implements the
card side of the DDV procedure exactly as the reference open-source client
hbci4java does (``org.kapott.hbci.smartcardio.DDVCardService0/1``):

* application selection for DDV type 0 (``D2 76 00 00 25 48 42 01 00``) and
  type 1 (``... 02 00``) cards
* EF_ID (card id, SFI 0x19), EF_BNK bank data records (SFI 0x1A), EF_SEQ
  signature counter (SFI 0x1C), EF_MAC (SFI 0x1B)
* key information (type 0: EF 0013/0014, type 1: GET KEYINFO)
* PIN verification (format-2 PIN block, ``00 20 00 81``) with retry counter
* MAC computation over a 20-byte hash block (``sign``) and session-key
  handling (``get_encryption_keys`` / ``decrypt``) via INTERNAL AUTHENTICATE

The HBCI/FinTS *message* protocol (dialogs with the bank server) is out of
scope for a reader toolkit; these primitives are what an HBCI client needs from
the card.  See ``ctapi.py`` for the CT-API interface HBCI software expects.
"""

from __future__ import annotations

from dataclasses import dataclass

from .channel import CardChannel
from .errors import CardError, UnsupportedCardError
from .iso7816 import Iso7816Card

AID_DDV_TYPE0 = bytes.fromhex("D27600002548420100")
AID_DDV_TYPE1 = bytes.fromhex("D27600002548420200")

SFI_EF_ID = 0x19
SFI_EF_BNK = 0x1A
SFI_EF_MAC = 0x1B
SFI_EF_SEQ = 0x1C
FID_EF_KEY_SIG = 0x0013   # type 0: signature key info
FID_EF_KEY_ENC = 0x0014   # type 0: encryption key info

CLA_STD = 0x00
CLA_EXT = 0xB0
CLA_SM_PROPR = 0x04       # type 0 MAC computation
CLA_SM1 = 0x08            # type 1 MAC computation
INS_GET_KEYINFO = 0xEE
KEY_TYPE_DF = 0x80
PWD_TYPE_DF = 0x80
SM_RESP_DESCR = 0xBA
SM_CRT_CC = 0xB4
SM_REF_INIT_DATA = 0x87
SM_VALUE_LE = 0x96

COMM_TYPES = {0: "T-Online (BTX)", 1: "T-Online", 2: "TCP/IP", 3: "HTTPS"}


@dataclass
class BankData:
    record: int
    shortname: str
    blz: str
    comm_type: int
    comm_addr: str
    comm_addr2: str
    country: str
    user_id: str

    def describe(self) -> dict[str, str]:
        return {"record": str(self.record), "bank": self.shortname, "BLZ": self.blz, "country": self.country,
                "communication": f"{COMM_TYPES.get(self.comm_type, self.comm_type)} {self.comm_addr}{self.comm_addr2}".strip(),
                "user id": self.user_id}

    @staticmethod
    def parse(record: int, raw: bytes) -> "BankData":
        if len(raw) < 88:
            raise ValueError(f"EF_BNK record is {len(raw)} bytes, expected at least 88")
        text = lambda a, b: raw[a:b].decode("latin-1").strip(" \x00")
        blz = ""
        for ch in raw[20:24]:
            for nibble in (ch >> 4, ch & 0x0F):
                if nibble > 9:
                    nibble ^= 0x0F
                blz += chr(nibble + 0x30)
        return BankData(record, text(0, 20), blz, raw[24], text(25, 53), text(53, 55), text(55, 58), text(58, 88))


@dataclass
class KeyData:
    num: int
    version: int
    length: int
    algorithm: int

    def describe(self) -> str:
        return f"key {self.num} version {self.version} length {self.length} alg {self.algorithm}"


class DDVCard:
    """A DDV (DES-DES-Verfahren) HBCI chip card."""

    def __init__(self, channel: CardChannel):
        self.iso = Iso7816Card(channel)
        self.card_type: int | None = None

    # -- selection -------------------------------------------------------------------------
    def select(self) -> int:
        """Select the DDV application; returns the card type (0 or 1)."""
        for card_type, aid in ((1, AID_DDV_TYPE1), (0, AID_DDV_TYPE0)):
            try:
                self.iso.select_aid(aid, return_fci=False)
                self.card_type = card_type
                return card_type
            except CardError:
                continue
        raise UnsupportedCardError("no DDV (HBCI) application on this card")

    def _ensure(self) -> None:
        if self.card_type is None:
            self.select()

    # -- files -------------------------------------------------------------------------------------
    def _read_record_sfi(self, sfi: int, idx: int) -> bytes:
        return self.iso.read_record(idx + 1, sfi=sfi)

    def _update_record_sfi(self, sfi: int, idx: int, data: bytes) -> None:
        self.iso.update_record(idx + 1, data, sfi=sfi)

    def card_id(self) -> str:
        self._ensure()
        return self._read_record_sfi(SFI_EF_ID, 0).decode("latin-1")

    def card_id_digits(self) -> str:
        """CID as printed on the card (BCD nibbles of the raw record)."""
        self._ensure()
        raw = self._read_record_sfi(SFI_EF_ID, 0)
        return "".join(f"{b >> 4}{b & 0x0F}" for b in raw).rstrip("F")

    def bank_data(self, idx: int) -> BankData | None:
        self._ensure()
        try:
            raw = self._read_record_sfi(SFI_EF_BNK, idx)
        except CardError as exc:
            if exc.sw in (0x6A83, 0x6A82):
                return None
            raise
        return BankData.parse(idx + 1, raw)

    def all_bank_data(self, max_records: int = 5) -> list[BankData]:
        out = []
        for i in range(max_records):
            bd = self.bank_data(i)
            if bd is None:
                break
            if bd.blz.strip("0") or bd.user_id:
                out.append(bd)
        return out

    def write_bank_data(self, idx: int, bank: BankData) -> None:
        """Rewrite an EF_BNK record (needs PIN); layout mirrors ``BankData.parse``."""
        self._ensure()
        raw = bytearray(self._read_record_sfi(SFI_EF_BNK, idx))
        raw[0:20] = bank.shortname.encode("latin-1").ljust(20)[:20]
        digits = bank.blz.rjust(8, "0")[:8]
        raw[20:24] = bytes(int(digits[i : i + 2], 16) for i in range(0, 8, 2))
        raw[24] = bank.comm_type
        raw[25:53] = bank.comm_addr.encode("latin-1").ljust(28)[:28]
        raw[53:55] = bank.comm_addr2.encode("latin-1").ljust(2)[:2]
        raw[55:58] = bank.country.encode("latin-1").ljust(3)[:3]
        raw[58:88] = bank.user_id.encode("latin-1").ljust(30)[:30]
        self._update_record_sfi(SFI_EF_BNK, idx, bytes(raw))

    def key_data(self) -> list[KeyData]:
        self._ensure()
        keys = []
        if self.card_type == 0:
            for fid, version_offset in ((FID_EF_KEY_SIG, 4), (FID_EF_KEY_ENC, 3)):
                self.iso.select_fid(fid, p2=0x0C)
                raw = self.iso.read_record(1, sfi=None)
                keys.append(KeyData(raw[0], raw[version_offset], raw[1], raw[2]))
        else:
            for idx, num in ((1, 2), (2, 3)):
                raw = self.iso.send(INS_GET_KEYINFO, KEY_TYPE_DF, idx + 1, le=256, cla=CLA_EXT).data
                keys.append(KeyData(num, raw[-1] if raw else 0, 16, 0))
        return keys

    def signature_counter(self) -> int:
        self._ensure()
        raw = self._read_record_sfi(SFI_EF_SEQ, 0)
        return (raw[0] << 8) | raw[1]

    def set_signature_counter(self, value: int) -> None:
        self._ensure()
        self._update_record_sfi(SFI_EF_SEQ, 0, value.to_bytes(2, "big"))

    # -- PIN -------------------------------------------------------------------------------------------
    @staticmethod
    def pin_block(pin: str) -> bytes:
        """ISO 9564 format-2 PIN block: 2N followed by BCD digits padded with F."""
        if not pin.isdigit() or not 4 <= len(pin) <= 12:
            raise ValueError("PIN must be 4..12 digits")
        return bytes.fromhex(f"2{len(pin):X}" + pin.ljust(14, "F"))

    def verify_pin(self, pin: str, pwd_id: int = 1) -> None:
        """VERIFY with the PIN typed on the PC (class 1 reader).  Raises CardError 63Cx / 6983."""
        self._ensure()
        self.iso.send(0x20, 0x00, PWD_TYPE_DF | pwd_id, self.pin_block(pin))

    def pin_tries_remaining(self, pwd_id: int = 1) -> int | None:
        self._ensure()
        return self.iso.verify_retries(PWD_TYPE_DF | pwd_id)

    # -- cryptography ------------------------------------------------------------------------------------
    def internal_authenticate(self, key_num: int, data8: bytes) -> bytes:
        if len(data8) != 8:
            raise ValueError("INTERNAL AUTHENTICATE input must be 8 bytes")
        return self.iso.internal_authenticate(data8, algorithm=0x00, reference=KEY_TYPE_DF | key_num, le=8)

    def get_challenge(self) -> bytes:
        return self.iso.get_challenge(8)

    def sign(self, hash20: bytes) -> bytes:
        """Compute the DDV MAC over a 20-byte (RIPEMD-160) hash: last 12 bytes go to EF_MAC,
        first 8 bytes are MAC'ed by the card with the signature key."""
        self._ensure()
        hash20 = bytes(hash20)
        if len(hash20) != 20:
            raise ValueError("DDV signs a 20-byte hash")
        self._update_record_sfi(SFI_EF_MAC, 0, hash20[8:20])
        return self.calculate_signature(hash20[:8])

    def calculate_signature(self, data8: bytes) -> bytes:
        if self.card_type == 0:
            self.iso.put_data(0x0100, data8)
            resp = self.iso.send(0xB2, 0x01, (SFI_EF_MAC << 3) | 0x04, le=256, cla=CLA_SM_PROPR)
            return resp.data[12:20]
        body = bytes([SM_RESP_DESCR, 0x0C, SM_CRT_CC, 0x0A, SM_REF_INIT_DATA, 0x08]) + data8 + bytes([SM_VALUE_LE, 0x01, 0x00])
        resp = self.iso.send(0xB2, 0x01, (SFI_EF_MAC << 3) | 0x04, body, 256, cla=CLA_SM1)
        return resp.data[16:24]

    def get_encryption_keys(self, key_num: int) -> tuple[bytes, bytes]:
        """Returns (plain 16-byte session key, its encryption under the card's encryption key)."""
        plain, enc = bytearray(16), bytearray(16)
        for i in range(2):
            challenge = self.get_challenge()
            plain[i * 8 : i * 8 + 8] = challenge
            enc[i * 8 : i * 8 + 8] = self.internal_authenticate(key_num, challenge)
        return bytes(plain), bytes(enc)

    def decrypt(self, key_num: int, enc16: bytes) -> bytes:
        enc16 = bytes(enc16)
        if len(enc16) != 16:
            raise ValueError("expected a 16-byte encrypted session key")
        return b"".join(self.internal_authenticate(key_num, enc16[i : i + 8]) for i in (0, 8))

    def info(self) -> dict[str, str]:
        t = self.select()
        out = {"card type": f"DDV type {t}", "card id": self.card_id_digits(),
               "signature counter": str(self.signature_counter())}
        for bd in self.all_bank_data():
            for k, v in bd.describe().items():
                out[f"bank[{bd.record}] {k}"] = v
        try:
            for k in self.key_data():
                out[f"key {k.num}"] = k.describe()
        except CardError as exc:
            out["keys"] = f"<unavailable: {exc.description}>"
        return out
