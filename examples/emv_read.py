"""Read the EMV application on an inserted payment card (read-only, PAN masked)."""

from omnikey3021 import OmnikeyReader
from omnikey3021.emv import EmvCard, TerminalData

with OmnikeyReader() as reader:
    reader.wait_for_card()
    with reader.connect() as session:
        print("ATR EMV compliance issues:", session.parsed_atr.emv_compliance() or "none")
        emv = EmvCard(session, TerminalData(country_code=0x0276, currency_code=0x0978))
        for app in emv.list_applications():
            print(app.aid.hex().upper(), app.label, app.scheme)
            data = emv.read_application(app)
            print("\n".join(data.describe(mask_pan=True)))
            print("ATC:", emv.transaction_counter(), "PIN tries:", emv.pin_try_counter())
