# omnikey3021-rw

Read/write toolkit and access-control system for the **HID OMNIKEY 3021** USB contact
smart card reader.  Pure Python (3.9+), no third-party packages: it talks to the
reader through the operating system's PC/SC service (`winscard.dll`, `PCSC.framework`
or `libpcsclite`) with a built-in ctypes binding.

> **Important - the 3021 is a contact reader.** It reads chip cards that are inserted
> (ISO 7816 CPU cards and SLE 4442 / SLE 4428 / I2C memory cards).  It has **no RFID/NFC
> antenna**, so it cannot read proximity badges, MIFARE or iCLASS tags.  If your access
> system needs tap-to-open badges you need an OMNIKEY 5021/5022/5422/5427 instead; the
> access layer here would still apply, but the card layer would not.

## What is supported

The reader's datasheet lists five specifications.  Each one maps to a layer of this toolkit
(details and byte-level tables in [docs/PROTOCOL_REFERENCE.md](docs/PROTOCOL_REFERENCE.md)):

| Datasheet item | What it means for the 3021 | Toolkit |
|---|---|---|
| **ISO 7816** | contact cards, classes A/B/C, T=0 and T=1 | `atr.py` (7816-3 ATR), `apdu.py` (short/extended APDUs), `iso7816.py` (7816-4 file/PIN/auth commands, 7816-8 security operations, 7816-9 file management), `memorycard.py` (7816-10 synchronous cards) |
| **EMVCo Terminal Level 1** | EMV-certified card interface, EMVCo operating mode | `ReaderConfig.set_operating_mode`, `ATR.emv_compliance()` (Book 1 ATR rules), `emv.py` read-only Level 2 (PSE/PPSE, GPO, AFL records, tags, ATC, log) |
| **USB CCID** | CCID 1.1 class device driven by the OS driver | `ccid.py` (class descriptor: voltages, clocks, data rates, IFSD, exchange level, features; sysfs discovery), PC/SC part 10 TLV properties (VID/PID, firmware id), CCID escape |
| **PC/SC** | host API (winscard / pcsc-lite) | `pcsc.py` ctypes binding: contexts, readers and groups, status change + hot-plug monitor, shared/exclusive/direct connect, reconnect, transactions, transmit, control, attributes |
| **Calypso** | transit ticketing; dual-interface cards work on the contact interface | `calypso.py` read path (application/serial/startup, files, records) + secure-session read/write with a `CalypsoSam` (a SAM in a second reader), simulated card + SAM for tests |
| **HBCI** | class 1 terminal for German home banking (DDV cards via CT-API) | `ctapi.py` (CT-API `CT_init/CT_data/CT_close` + CT-BCS over PC/SC, or a vendor CT-API library), `hbci.py` (DDV card: card id, bank records, PIN, MAC/sign, session keys, signature counter) |

On top of that:

| Area | Support |
|---|---|
| Asynchronous CPU cards | T=0 and T=1, short and extended APDUs, automatic `61xx`/`6Cxx` handling, ENVELOPE for T=0; SELECT (MF/FID/AID/path), READ/UPDATE/WRITE/ERASE BINARY, READ/UPDATE/APPEND/SEARCH RECORD, VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER, GET CHALLENGE, INTERNAL/EXTERNAL/GENERAL AUTHENTICATE, GET/PUT DATA, MANAGE CHANNEL, MSE, PSO (sign/decipher/encipher/hash/verify certificate), GENERATE KEY PAIR, CREATE/DELETE/ACTIVATE/DEACTIVATE/TERMINATE FILE, FCI/FCP parsing |
| Synchronous memory cards | SLE 4432/4442 (2-wire), SLE 4418/4428 (3-wire), I2C EEPROMs (27 predefined types + custom): read, write, PSC verify/change, protection bits, compare-and-protect, error counter; plus raw 2WBP/3WBP/I2C bus commands |
| Reader configuration (vendor API) | capabilities (product, firmware, serial, ...), exchange level (TPDU/APDU/extended), voltage class sequence (5 V / 3 V / 1.8 V), ISO vs EMVCo mode, 1 KiB user EEPROM, reboot, factory reset |
| Access control | signed 64-byte credential on the card (HMAC-SHA256, bound to the physical card), SQLite registry of holders/cards/events, revocation, expiry, per-level time schedules, optional challenge/response for CPU cards, door-controller loop with shell/webhook hooks |
| Simulator | simulated reader with SLE 4442, ISO 7816 (T=1 or T=0 style), EMV and HBCI DDV cards so everything can be developed and tested without hardware |

## Install

```bash
# Linux: PC/SC daemon + CCID driver
sudo apt install pcscd libccid libpcsclite1      # Debian/Ubuntu
sudo systemctl enable --now pcscd
# macOS: nothing to install (PCSC.framework is built in)
# Windows: nothing to install (Smart Card service + Microsoft CCID driver)

pip install .            # or: pip install -e .
omnikey3021 readers      # should print "HID Global OMNIKEY 3x21 Smart Card Reader ..."
```

No HID driver is needed; the reader is CCID compliant.  On Windows, vendor
commands sent while **no card** is inserted go through the CCID escape and require
the registry value described in the protocol reference; with a card inserted they
work out of the box.

## Command line

```bash
omnikey3021 info                       # reader capabilities, slot config, card ATR
omnikey3021 wait                       # block until a card is inserted, print its ATR
omnikey3021 atr 3B 04 A2 13 10 91      # decode any ATR offline

# raw APDUs (auto GET RESPONSE / 6C handling)
omnikey3021 apdu "00 A4 04 00 08 A000000003021001" "00 84 00 00 08"
omnikey3021 script commands.apdu       # file of APDUs with 'expect 9000' checks

# ISO 7816 CPU cards
omnikey3021 iso select --aid A000000003021001
omnikey3021 iso read --fid 0002 --length 64
omnikey3021 iso write --fid 0002 --pin 1234 --offset 0 --verify "str:hello"
omnikey3021 iso verify                 # remaining PIN tries
omnikey3021 iso records --fid 2F02

# memory cards (SLE 4442 shown; --kind sle4428 / i2c to force)
omnikey3021 mem info
omnikey3021 mem read --addr 0 --length 256
omnikey3021 mem verify FFFFFF          # factory PSC of most blank SLE 4442
omnikey3021 mem write --addr 64 --psc FFFFFF --verify "str:hello card"
omnikey3021 mem change-psc FFFFFF 123456
omnikey3021 mem protection             # show protection bits
omnikey3021 mem protect --addr 0 --length 32 --yes   # IRREVERSIBLE
omnikey3021 mem read --kind i2c --i2c-type AT24C64 --length 128
omnikey3021 mem i2c-types

# EMV payment cards (read-only)
omnikey3021 emv apps                   # applications from the PSE (or AID probing)
omnikey3021 emv read --country 0276 --currency 0978   # PAN (masked), expiry, AIP, CVM list, ATC ...
omnikey3021 emv log                    # transaction log if the card keeps one
omnikey3021 atr --emv                  # EMV Book 1 ATR compliance check

# HBCI / FinTS DDV banking cards
omnikey3021 hbci info                  # card id, bank records (BLZ, user id, host), keys, signature counter
omnikey3021 hbci pin 12345
omnikey3021 hbci sign --pin 12345 <20-byte-hash-hex>
omnikey3021 hbci keys --pin 12345 --derive 3
omnikey3021 ctapi "20 12 01 01 01 0F 00" "20 13 00 80"     # CT-API / CT-BCS over PC/SC
omnikey3021 ctapi --dad icc "00 A4 04 00 08 A000000003021001"

# Calypso transport cards (contact / dual-interface)
omnikey3021 calypso info               # AID, serial, startup info, files
omnikey3021 calypso dump               # every record of the standard transport files
omnikey3021 calypso read --sfi 0x08    # event log
omnikey3021 calypso write --sfi 0x09 --record 1 --data @contract.bin --sam-reader "OMNIKEY ... 1"  # needs a SAM
omnikey3021 calypso counter --sfi 0x19 --decrease 1 --sam-reader "OMNIKEY ... 1"

# USB CCID and PC/SC
omnikey3021 ccid                       # CCID class descriptor (Linux sysfs) + part 10 properties
omnikey3021 monitor                    # card insert/remove and reader hot-plug events
omnikey3021 readers --groups
omnikey3021 --exclusive apdu "00 A4 04 00"

# reader configuration (settings apply after a reader restart)
omnikey3021 reader caps
omnikey3021 reader slot --voltage 5V,3V,1.8V --exchange-level apdu --mode iso
omnikey3021 reader eeprom 0 16
omnikey3021 reader eeprom 0 --data "str:site-A"
omnikey3021 reader reboot
```

Global options: `--reader NAME`, `--protocol t0|t1`, `--timeout S`, `--trace`
(print every APDU), `--simulate sle4442|iso|iso-t0|emv|hbci|calypso|empty` (+ `--sim-state FILE` to
keep the simulated card between commands).

## Access-control system

```bash
omnikey3021 access init --site-code 7            # creates access.sqlite3 + site.key (keep secret!)
omnikey3021 access holder add "Peter" --level 2
omnikey3021 access enroll --holder Peter --psc FFFFFF --expires-days 365 --protect-binding
omnikey3021 access check                          # decide once for the inserted card
omnikey3021 access schedule add --level 1 --days mon-fri --start 07:00 --end 19:00
omnikey3021 access monitor --exec 'gpioset gpiochip0 17=1 && sleep 3 && gpioset gpiochip0 17=0'
omnikey3021 access monitor --webhook http://door-controller/open
omnikey3021 access revoke 12
omnikey3021 access cards
omnikey3021 access log -n 100
```

How it works, and what it does and does not protect against, is in
[docs/ACCESS_SYSTEM.md](docs/ACCESS_SYSTEM.md).  Short version: every card carries a
64-byte block signed with your site key and bound to the card's own manufacturer
area (memory cards) or chip serial (CPU cards).  Editing, forging or copying the
block to a different card fails.  A bit-for-bit clone of an SLE 4442 including its
manufacturer area is the residual risk of using memory cards; CPU cards with
`--iso-challenge` close that gap.

## Python API

```python
from omnikey3021 import OmnikeyReader, Iso7816Card, open_memory_card, ReaderConfig

with OmnikeyReader() as reader:                 # first OMNIKEY reader
    reader.wait_for_card()
    with reader.connect() as card:              # CardSession: transmit/control/atr/protocol
        print(card.parsed_atr.describe())
        if card.parsed_atr.is_memory_card:
            mem = open_memory_card(card)        # SLE4442Card / SLE4428Card / I2CCard
            mem.verify_psc(bytes.fromhex("FFFFFF"))
            mem.write(64, b"hello", verify=True)
        else:
            iso = Iso7816Card(card)
            iso.select_aid(bytes.fromhex("A000000003021001"))
            print(iso.read_binary(0, 32))
        print(ReaderConfig(card).capabilities())
```

Module map: `pcsc` (ctypes PC/SC + `CardMonitor`), `reader`, `atr`, `apdu`, `tlv`, `iso7816`
(+ `Iso7816CardExtended`), `memorycard`, `vendor`, `emv`, `ccid`, `hbci`, `ctapi`, `calypso`,
`access/` (`credential`, `store`, `controller`), `simulator`, `cli`.  More in [examples/](examples/).

## Try it without a reader

```bash
omnikey3021 --simulate sle4442 --sim-state /tmp/card info
omnikey3021 --simulate sle4442 --sim-state /tmp/card mem write --addr 64 --psc FFFFFF "str:hi"
omnikey3021 --simulate iso-t0 iso read --fid 0002 --length 32
omnikey3021 --simulate emv emv read
omnikey3021 --simulate hbci hbci info
python -m unittest discover -s tests
```

## Verified against hardware?

Not yet.  Everything was built from HID's developer guide and ISO 7816 and is
exercised against the simulator (byte-exact checks of the APDUs printed in the guide,
EMV/HBCI flows checked against the hbci4java and EMV Book conventions).  Two details are inferred rather than documented and are marked
**(assumption)** in the protocol reference: the I2C READ payload layout and the
3WBP control words other than the two the guide prints.  Please run
`omnikey3021 --trace info` and `mem info` with your reader and cards and report the
output if anything disagrees.

## License

MIT.
