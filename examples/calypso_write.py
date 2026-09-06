"""Write a Calypso card inside a secure session, with a Calypso SAM in a second reader.

Writing REQUIRES a SAM personalised with the same keys as your cards.  For a
closed system (your own buses) you buy Calypso cards and a matching SAM from a
Calypso vendor, put the SAM in a second OMNIKEY 3021, and run this.
"""

from omnikey3021 import OmnikeyReader
from omnikey3021.calypso import CalypsoCard, PcscSam, SFI_CONTRACTS

readers = OmnikeyReader.list()
assert len(readers) >= 2, "need two readers: one for the card, one for the SAM"

with OmnikeyReader(readers[0]) as card_reader, OmnikeyReader(readers[1]) as sam_reader:
    card_reader.wait_for_card()
    with card_reader.connect() as card_session, sam_reader.connect() as sam_session:
        card = CalypsoCard(card_session)
        card.select_application()
        sam = PcscSam(sam_session)
        card.open_secure_session(sam, key_index=1)           # 1 = debit key
        try:
            card.update_record(SFI_CONTRACTS, 1, b"\x02" + b"\x00" * 28)
            card.close_secure_session()                      # verifies the card's MAC via the SAM
            print("write committed and authenticated")
        except Exception:
            card.abort_secure_session()
            raise
