"""Write a Calypso card inside a secure session.

Writing REQUIRES a Calypso SAM personalised with the same keys as your cards.  This
example shows the full flow and how to plug in a real SAM (``PcscSam`` in a second
reader).  Without a SAM the card falls back to a read-only open session and any write
raises ``CalypsoNoSamError`` - run with ``--simulate`` to exercise the whole flow
against a simulated SAM + card:

    python examples/calypso_write.py --simulate

Key indexes (selected on the SAM):
    KEY_DEBIT (1)          debit / read
    KEY_RELOAD (2)         reload / top-up
    KEY_PERSONALIZATION (3) issuer / structural writes
"""

from __future__ import annotations

import sys

from omnikey3021.calypso import (
    CalypsoCard, CalypsoNoSamError, CalypsoSession, KEY_DEBIT, SFI_CONTRACTS, SFI_COUNTERS,
)


def do_write(card: CalypsoCard, sam) -> None:
    card.auto_select()
    card.attach_sam(sam)                         # attach the SAM; None => read-only

    if not card.has_sam:
        # No SAM: demonstrate the graceful read-only fallback.
        with CalypsoSession(card):               # open (read-only) session
            print("Contracts:", [r.data[:2].hex() for r in card.read_contracts()])
        try:
            with CalypsoSession(card):
                card.update_record(SFI_CONTRACTS, 1, b"\x02" + b"\x00" * 28)
        except CalypsoNoSamError as exc:
            print(f"write correctly refused without a SAM: {exc}")
        return

    # With a SAM: open a secure session, write, and let the context manager close it
    # (which verifies the card's MAC via the SAM) - or abort on error.
    with CalypsoSession(card, sam, key_index=KEY_DEBIT):
        card.update_record(SFI_CONTRACTS, 1, b"\x02" + b"\x00" * 28)
        new_counter = card.increase_counter(SFI_COUNTERS, 0, 5)
        print(f"counter after increase: {int.from_bytes(new_counter, 'big')}")
    print("write committed and authenticated by the SAM")


def main() -> None:
    if "--simulate" in sys.argv:
        from omnikey3021.simulator import SimulatedCalypsoCard, SimulatedReader, SimulatedSam

        key = b"\x07" * 16                        # SAM and card must share the key
        channel = SimulatedReader(SimulatedCalypsoCard(key=key)).connect()
        do_write(CalypsoCard(channel), SimulatedSam(key))
    else:
        from omnikey3021 import OmnikeyReader
        from omnikey3021.calypso import PcscSam

        readers = OmnikeyReader.list()
        assert len(readers) >= 2, "need two readers: one for the card, one for the SAM"
        with OmnikeyReader(readers[0]) as card_reader, OmnikeyReader(readers[1]) as sam_reader:
            card_reader.wait_for_card()
            with card_reader.connect() as card_session, sam_reader.connect() as sam_session:
                do_write(CalypsoCard(card_session), PcscSam(sam_session))


if __name__ == "__main__":
    main()
