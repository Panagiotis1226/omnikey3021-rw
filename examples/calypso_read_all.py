"""Read *everything* off a Calypso transport card in an open session (no SAM needed).

Open-access reads work on OPUS / Navigo / MOBIB / Oura and most Calypso cards through
the contact interface.  This walks the standard transport files (serial, environment,
contracts, event log, counters) and shows how to open a Calypso *open session*
(ratification mode) without a SAM for read access to session-protected files.

Run against real hardware, or hardware-free with the simulator:

    python examples/calypso_read_all.py --simulate
"""

from __future__ import annotations

import sys


def read_all(card) -> None:
    ident = card.auto_select()                       # try the known Calypso AIDs in turn
    print("\n".join(ident.describe()))
    print(f"Detected profile: {card.profile}")

    print(f"\nCard serial number (CSN): {card.read_serial().hex().upper()}")

    env = card.read_environment()
    if env:
        print(f"\nEnvironment & Holder: {env.data.hex(' ').upper()}")

    print("\nContracts:")
    for rec in card.read_contracts():
        print(f"  contract {rec.number}: {rec.data.hex(' ').upper()}")

    print("\nEvent log:")
    for rec in card.read_event_log():
        print(f"  event {rec.number}: {rec.data.hex(' ').upper()}")

    counters = card.read_counters()
    print(f"\nCounters: {counters}")

    # An open session (no SAM) gives read access to session-protected files too.
    from omnikey3021.calypso import CalypsoSession

    with CalypsoSession(card):                        # no SAM -> read-only open session
        env_in_session = card.read_environment()
        print(f"\nRead inside open session OK: "
              f"{env_in_session.data.hex(' ').upper() if env_in_session else '(empty)'}")


def main() -> None:
    if "--simulate" in sys.argv:
        from omnikey3021.calypso import CalypsoCard
        from omnikey3021.simulator import SimulatedCalypsoCard, SimulatedReader

        channel = SimulatedReader(SimulatedCalypsoCard()).connect()
        read_all(CalypsoCard(channel))
    else:
        from omnikey3021 import OmnikeyReader
        from omnikey3021.calypso import CalypsoCard

        with OmnikeyReader() as reader:
            reader.wait_for_card()
            with reader.connect() as session:
                read_all(CalypsoCard(session))


if __name__ == "__main__":
    main()
