"""Talk to an HBCI DDV banking card: bank records, PIN, MAC and session key (what a FinTS client needs)."""

import getpass
import hashlib

from omnikey3021 import OmnikeyReader
from omnikey3021.hbci import DDVCard

with OmnikeyReader() as reader:
    reader.wait_for_card()
    with reader.connect() as session:
        card = DDVCard(session)
        print("DDV type", card.select())
        print("card id", card.card_id_digits())
        for bank in card.all_bank_data():
            print(bank.describe())
        card.verify_pin(getpass.getpass("card PIN: "))
        # HBCI signs a RIPEMD-160 hash of the message; use SHA-1 as a stand-in when hashlib lacks ripemd160
        digest = hashlib.new("ripemd160", b"message").digest() if "ripemd160" in hashlib.algorithms_available \
            else hashlib.sha1(b"message").digest()
        print("MAC:", card.sign(digest).hex())
        plain, enc = card.get_encryption_keys(3)
        print("session key:", plain.hex(), "encrypted:", enc.hex())
        card.set_signature_counter(card.signature_counter() + 1)
