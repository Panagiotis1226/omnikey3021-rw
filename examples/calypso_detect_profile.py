"""Detect the Calypso profile (Prime / Light / Basic) of a card at selection time.

The profile is decided from the startup-info platform byte first, then the application
type, then the selected AID.  It is stored on the CalypsoCard as ``card.profile``.

    python examples/calypso_detect_profile.py --simulate
"""

from __future__ import annotations

import sys

from omnikey3021.calypso import CalypsoCard, CalypsoProfile


def show(card: CalypsoCard) -> CalypsoProfile:
    ident = card.auto_select()
    print(f"AID selected : {ident.aid.hex().upper()}")
    if ident.startup:
        print(f"Startup info : {ident.startup.raw.hex(' ').upper()}")
        print(f"  platform   : {ident.startup.describe()['platform']}")
    print(f"=> Profile   : {card.profile}")
    return card.profile


def main() -> None:
    if "--simulate" in sys.argv:
        from omnikey3021.simulator import SimulatedCalypsoCard, SimulatedReader

        for label, sim in (("Prime", SimulatedCalypsoCard()),
                           ("Light", SimulatedCalypsoCard.light()),
                           ("Basic", SimulatedCalypsoCard.basic())):
            print(f"\n=== simulated {label} card ===")
            show(CalypsoCard(SimulatedReader(sim).connect()))
    else:
        from omnikey3021 import OmnikeyReader

        with OmnikeyReader() as reader:
            reader.wait_for_card()
            with reader.connect() as session:
                show(CalypsoCard(session))


if __name__ == "__main__":
    main()
