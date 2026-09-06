"""Read a Calypso transport card (OPUS, Navigo, MOBIB, Oura...) over the contact interface.

No security module is needed for reading the free-access files.  The record
contents are network-specific (Intercode etc.), so they print as raw bytes.
"""

from omnikey3021 import OmnikeyReader
from omnikey3021.calypso import CalypsoCard, STANDARD_SFIS

with OmnikeyReader() as reader:
    reader.wait_for_card()
    with reader.connect() as session:
        card = CalypsoCard(session)
        ident = card.select_application()          # 1TIC.ICA by default, CLA 94 fallback for Rev2
        print("\n".join(ident.describe()))
        for sfi, records in card.dump().items():
            print(f"\nEF {sfi:02X} ({STANDARD_SFIS.get(sfi, 'file')}):")
            for r in records:
                print(f"  rec {r.number}: {r.data.hex(' ').upper()}")
