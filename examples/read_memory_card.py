"""Dump an SLE 4442 and write a string into its user area."""

from omnikey3021 import CardError, OmnikeyReader, open_memory_card

PSC = bytes.fromhex("FFFFFF")  # factory default of most blank SLE 4442 cards

with OmnikeyReader() as reader:
    print("reader:", reader.name)
    reader.wait_for_card()
    with reader.connect() as session:
        print("\n".join(session.parsed_atr.describe()))
        card = open_memory_card(session)           # SLE4442Card / SLE4428Card from the ATR
        print(card.info())
        dump = card.dump()
        print(dump.hex(" "))
        try:
            card.verify_psc(PSC)
        except CardError as exc:
            print("PSC rejected:", exc.description)
            raise SystemExit(1)
        card.write(100, b"hello from omnikey3021", verify=True)
        print("user area now:", card.read(100, 22))
