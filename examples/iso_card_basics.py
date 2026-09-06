"""Select an application on a CPU card, read a file and run a PIN check."""

from omnikey3021 import CardError, Iso7816Card, OmnikeyReader

AID = bytes.fromhex("A000000003021001")  # replace with your application's AID

with OmnikeyReader() as reader:
    reader.wait_for_card()
    with reader.connect() as session:
        session.trace = True  # print every APDU
        iso = Iso7816Card(session)
        try:
            fci = iso.select_aid(AID)
            print("\n".join(fci.describe()))
        except CardError as exc:
            print("no such application:", exc)
        fci = iso.select_mf()
        print("\n".join(fci.describe()))
        tries = iso.verify_retries()
        print("PIN tries remaining:", tries)
        challenge = iso.get_challenge(8)
        print("card challenge:", challenge.hex())
