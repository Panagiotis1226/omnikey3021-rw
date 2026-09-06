# OMNIKEY 3021 protocol reference

Byte-level summary of everything this toolkit sends to the reader, taken from the
HID *OMNIKEY Contact Smart Card Readers Software Developer Guide* (PLT-03099,
rev A.0, Feb 2017 - covers the OMNIKEY 3021, 3121, 3121 RB and 6121) and
ISO/IEC 7816-3/-4.  Where the guide is ambiguous the assumption made here is
marked **(assumption)** so it can be checked on real hardware.

## 1. What the 3021 is (and is not)

| Property | Value |
|---|---|
| Interface | USB 2.0 full speed, CCID 1.1 class device (works with the OS CCID driver, no vendor driver needed) |
| Card interface | **Contact only** (ISO 7816 landing contacts). No RFID/NFC/iCLASS. For contactless badges use an OMNIKEY 5x21/5x22/5427 |
| Voltage classes | A (5 V), B (3 V), C (1.8 V); selection sequence configurable |
| Async protocols | T=0, T=1 (TPDU, APDU or extended-APDU exchange level; extended APDU for T=1 only, T=0 uses ENVELOPE) |
| Sync (memory) cards | 2-wire SLE 4432/4442, 3-wire SLE 4418/4428, I2C EEPROM (S=8/9/10) - T=0 emulated by the reader |
| Operating modes | ISO/IEC 7816 (default) or EMVCo (5 V only, no sync cards) |
| Extras | 1024 byte user EEPROM, LED, low-power/wake-up |
| PC/SC names | Linux/macOS libccid: `HID Global OMNIKEY 3x21 Smart Card Reader`; Windows: `HID Global OMNIKEY Smart Card Reader 0` / `OMNIKEY CardMan 3x21` (legacy driver) |

## 2. PC/SC control codes

`SCARD_CTL_CODE(n)` is `0x42000000 + n` on pcsc-lite/macOS and `(0x31 << 16) | (n << 2)` on Windows.

| Name | n | Use |
|---|---|---|
| `CM_IOCTL_GET_FEATURE_REQUEST` | 3400 | PC/SC v2 part 10 feature list (TLV: tag, len=4, big-endian control code) |
| `IOCTL_CCID_ESCAPE` | 3500 | CCID escape - carries the vendor APDU below when no card is present (`SCARD_SHARE_DIRECT`) |
| `CM_IOCTL_GET_FW_VERSION` | 3001 | Legacy HID driver only |

Windows + Microsoft CCID driver: escape commands are blocked unless the DWORD
`EscapeCommandEnable` = 1 exists under
`HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_076B&PID_xxxx\<serial>\Device Parameters\WUDFUsbccidDriver`
(PLT-03099 appendix A).  Vendor commands sent as APDUs through `SCardTransmit`
(card inserted) do **not** need this.

## 3. Vendor command (chapter 6)

```
FF 70 07 6B Lc <DER-TLV> [Le]        P1P2 = 076Bh = HID vendor id
```

Response: `<TLV> 90 00`. Response tags: `9D` (primitive data), `BD` (constructed),
`9E 02 <cycle> <code>` (firmware error - SW still 9000).

Error codes: 03 NOT_SUPPORTED, 04 TLV_NOT_FOUND, 05 TLV_MALFORMED, 06 ISO_EXCEPTION,
0B/0C/0D/0F persistent memory errors, 11 INVALID_STORE_OPERATION, 13 TLV_INVALID_STRENGTH,
14 TLV_INSUFFICIENT_BUFFER, 15 DATA_OBJECT_READONLY, 1F APPLICATION_EXCEPTION,
2A MEDIA_TRANSMIT_EXCEPTION, 2B SAM_INSUFFICIENT_MSGHEADER, 2F TLV_INVALID_INDEX,
30 SECURITY_STATUS_NOT_SATISFIED, 31 TLV_INVALID_VALUE, 32 TLV_INVALID_TREE,
40 RANDOM_INVALID, 41 OBJECT_NOT_FOUND.

### 3.1 readerInformationApi (A2) - chapter 9

| Purpose | APDU | Typical response |
|---|---|---|
| GET capability *tag* | `FF 70 07 6B 08 A2 06 A0 04 A0 02 <tag> 00 00` | `BD len <tag> len value 90 00` |
| GET slot setting *tag* | `FF 70 07 6B 0A A2 08 A0 06 A3 04 A0 02 <tag> 00 00` | `BD 03 <tag> 01 xx 90 00` |
| SET slot setting *tag*=xx | `FF 70 07 6B 0B A2 09 A1 07 A3 05 A0 03 <tag> 01 xx 00` | `9D 00 90 00` |
| Read EEPROM n bytes @off | `FF 70 07 6B 0D A2 0B A0 09 A7 07 81 02 <off> 82 01 <n> 00` | `9D n data 90 00` |
| Write EEPROM data @off | `FF 70 07 6B Lc A2 .. A1 .. A7 .. 81 02 <off> 83 <n> <data> 00` | `9D 00 90 00` |
| Reboot | `FF 70 07 6B 09 A2 07 A1 05 A9 03 80 01 00 00` | `9D 00 90 00` |
| Factory defaults | `FF 70 07 6B 09 A2 07 A1 05 A9 03 81 01 00 00` | `9D 00 90 00` |

readerCapabilities (A0, read only) tags: 80 tlvVersion, 81 deviceID, 82 productName,
83 productPlatform, 85 firmwareVersion (major, minor, revision), 89 hardwareVersion,
8A hostInterfaces (bit1 = USB), 8B numberOfContactSlots, 8F vendorName, 91 exchangeLevel,
92 serialNumber, 94 sizeOfUserEEProm, 96 firmwareLabel.

contactSlotConfiguration (A3 / A0 = slot 0 **(assumption: inner A0 addresses slot 0)**):

| Tag | Setting | Values |
|---|---|---|
| 80 | exchangeLevel | 01 TPDU, 02 APDU, 04 extended APDU (section 5.3 prints 03 for the same level) |
| 82 | voltageSequence | bits 1-0 first class, 3-2 second, 5-4 third; 01 = 1.8 V, 10 = 3 V, 11 = 5 V; 00 = automatic. `1B` = 5V->3V->1.8V, `39` = 1.8V->3V->5V |
| 83 | operatingMode | 00 ISO/IEC 7816, 01 EMVCo |

Settings take effect after a reader restart.

### 3.2 synchronousCardCommand (A6) - section 8.2, raw bus access

| Bus | Tag | Payload | Example |
|---|---|---|---|
| 2WBP (SLE 4432/42) | A0 | control, address, data | `FF 70 07 6B 07 A6 05 A0 03 30 AA 00 00` reads byte 0xAA -> `BD 03 A0 01 55 90 00` |
| 3WBP (SLE 4418/28) | A1 | control (A9 A8 S5..S0), address A7..A0, data | `FF 70 07 6B 07 A6 05 A1 03 0C AA 00 00` -> `BD 04 A1 02 AA 80 90 00` (data AA, protect bit set) |
| I2C | A2 | addrLen(1..3), count(<=32), devAddr, sub1, sub2, [data] | `FF 70 07 6B 09 A6 07 A2 05 03 10 A1 01 00 00` reads 16 bytes @0x0100 |

The guide's table lists I2C as tag A0 but all its examples use A2; A2 is used here.
The guide prints `99 00` as the SW of the 2WBP examples; the toolkit accepts both 9000 and 9900.

2WBP control bytes (SLE 4442 datasheet): 30 read main, 38 update main, 34 read protection,
3C write protection, 31 read security, 39 update security, 33 compare verification data.
3WBP control words (SLE 4428 datasheet, A9A8 = 00): 0C read 9 bit, 0E read 8 bit,
31 write with protect, 33 write without protect, 30 write protect bit with compare,
32 write error counter (addr 3FD), 35 verify PIN byte (addr 3FE/3FF) **(3WBP values other
than 0C/33 are from the Siemens datasheet, not printed legibly in the guide)**.

## 4. Memory cards through PC/SC (section 8.1)

The reader emulates T=0 and reports a pseudo ATR (`3B 04 A2 13 10 91` for SLE 4442-type
cards, `3B 04 92 23 10 91` for SLE 4428-type; composed from the line state for I2C cards).

| Command | APDU | Notes / status words |
|---|---|---|
| READ BINARY | `FF B0 <hi> <lo> Le` | Le=00 reads to end (max 256). 6282 EOF, 6982 PSC needed, 6A82 bad address, 6Cxx wrong Le |
| UPDATE BINARY | `FF D6 <hi> <lo> Lc data` | 6581 write failed (protected byte), 6982 PSC not presented |
| VERIFY (PSC) | `FF 20 00 00 Lc PIN` | 3 bytes SLE 4442 (3 tries), 2 bytes SLE 4428 (8 tries). 63Cx tries left, 6983 blocked |
| MODIFY (change PSC) | `FF 21 00 00 Lc old+new` | same status words as VERIFY |
| READ PROTECTION MEMORY | `FF 3A <hi> <lo> Le` | one byte per address, bit0 = protected |
| COMPARE AND PROTECT | `FF 30 00 03 Lc 01 00 00 <hi> <lo> data` | irreversible; response carries the failing address before SW on error |
| I2C INIT | `FF 30 00 04 08 01 <type> <page> <nAddr> <size:4>` | type table in `memorycard.I2C_TYPES` (00 = custom parameters) |
| I2C READ | `FF 30 00 05 09 01 <addr:4> <len:4>` | **(assumption: the 4 bytes after the address are the read length - the guide's table is garbled but Lc=09)** |
| I2C WRITE | `FF 30 00 06 Lc 01 <addr:4> data` | max 250 bytes per command |

SLE 4442 layout: bytes 0-31 manufacturer/issuer area with 32 protection bits
(irreversible), 32-255 user area (write needs PSC), security memory = error counter +
3-byte PSC (PSC only readable after successful verification).
SLE 4428 layout: 1024 bytes each with a protect bit, error counter @1021, PSC @1022-1023.

## 5. Asynchronous cards (chapter 7 / ISO 7816-4)

Standard APDUs are forwarded unchanged.  Cases: `CLA INS P1 P2` / `+Le` / `+Lc data` /
`+Lc data Le`; extended Lc = `00 hi lo`, Le = `(00) hi lo` (T=1 + reader in extended level).
Under T=0 the toolkit handles `61 xx` (GET RESPONSE `00 C0 00 00 xx`) and `6C xx`
(retry with Le=xx) transparently.  Commands implemented in `iso7816.py`: SELECT (MF, FID,
DF, EF, parent, AID, path), READ/UPDATE/WRITE/ERASE BINARY (chunked), READ/UPDATE/APPEND
RECORD, VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER, GET CHALLENGE,
INTERNAL/EXTERNAL AUTHENTICATE, GET/PUT DATA, GET RESPONSE, ENVELOPE, MANAGE CHANNEL.

## 6. ATR

`atr.py` decodes TS, T0, TA/TB/TC/TD chains, protocols, Fi/Di/fmax (TA1), specific mode
(TA2), voltage class indicator (TA for T=15), T=1 IFSC/BWI/CWI/checksum, historical bytes
and TCK validity, and recognises the synchronous pseudo ATRs above.

## 7. EMVCo Level 1 / Level 2 (`emv.py`)

Level 1 (electrical, T=0/T=1 timing, ATR rules) is certified in the reader itself; the
toolkit exposes the reader's **EMVCo operating mode** (`reader slot --mode emvco`: 5 V
only, no synchronous cards) and checks a card's ATR against **EMV Book 1 §8.3**
(`atr --emv`, `ATR.emv_compliance()`): TS, TA1/TA2 (no negotiable mode), TB1 = 00, TC1 ∈ {00, FF},
TD1/TD2 protocol nibbles, TC2 = 0A, TA3 ∈ 10..FE, BWI ≤ 4, CWI ≤ 5, TC3 = 00, TCK, ≤ 15 historical bytes.

Level 2 read-only flow implemented by `EmvCard`:

| Step | APDU |
|---|---|
| Select PSE / PPSE | `00 A4 04 00 0E 31 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00` (`1PAY.SYS.DDF01`; `2PAY...` for the PPSE) |
| Read directory | `00 B2 <rec> <SFI<<3 \| 04> 00` until `6A 83`; application templates `61 { 4F AID, 50 label, 87 priority }` |
| AID probing | SELECT of each entry in `KNOWN_AIDS` when there is no PSE |
| Select application | `00 A4 04 00 Lc AID 00` → FCI `6F { 84, A5 { 50, 87, 9F38 PDOL, 5F2D, BF0C { 9F4D log entry } } }` |
| GET PROCESSING OPTIONS | `80 A8 00 00 Lc 83 <len> <PDOL data> 00`; response `80 AIP AFL` or `77 { 82 AIP, 94 AFL }` |
| Read records | one READ RECORD per AFL entry (SFI, first, last, offline-auth count) |
| GET DATA | `80 CA 9F 36` ATC, `9F 17` PIN try counter, `9F 13` last online ATC, `9F 4F` log format |
| Transaction log | READ RECORD on the SFI named by `9F4D`, decoded with the `9F4F` format list |

`TerminalData` fills PDOL/CDOL requests (9F1A, 5F2A, 9F02, 9F03, 9C, 9F35, 9F33, 9F40, 9F66,
95, 9A, 9F37, 9F21).  The PAN is masked in CLI output unless `--unmask` is given.  No
transaction (GENERATE AC, authentication, scripts) is ever performed.

## 8. USB CCID (`ccid.py`)

The 3021 is a CCID 1.1 device (USB `076B:3021`, class 0x0B, one bulk-in, one bulk-out and
one interrupt-in endpoint).  The host does not talk CCID directly (the OS driver does), but
the reader's declared capabilities are visible:

* **CCID class descriptor** (54 bytes, type 0x21): bcdCCID, slots, `bVoltageSupport` (5 V/3 V/1.8 V),
  `dwProtocols` (T=0/T=1), default/max clock, default/max data rate, `dwMaxIFSD`,
  `dwSynchProtocols` (2-wire/3-wire/I2C), `dwMechanical`, `dwFeatures` (auto voltage, auto PPS,
  auto IFSD, TPDU / short / extended APDU level, clock stop ...), `dwMaxCCIDMessageLength`,
  `bClassGetResponse`, `bClassEnvelope`, `bPINSupport`.  Read from sysfs on Linux
  (`omnikey3021 ccid`), or parse any descriptor dump with `parse_class_descriptor`.
* **PC/SC part 10 GET_TLV_PROPERTIES** (control code from the feature list): USB VID/PID,
  firmware id, max APDU size, PPDU support - cross-platform via `CardSession.tlv_properties()`.
* **CCID escape** (`PC_to_RDR_Escape`, 0x6B): `CardSession.escape()` carries the vendor APDU
  of section 3 when no card is inserted.
* Message type constants (`PC_TO_RDR`, `RDR_TO_PC`) for interpreting traces.

## 9. PC/SC (`pcsc.py`, `reader.py`)

`SCardEstablishContext/ReleaseContext/IsValidContext/Cancel`, `SCardListReaders`,
`SCardListReaderGroups`, `SCardGetStatusChange` (incl. `\\?PnP?\Notification` hot-plug),
`SCardConnect` (shared / exclusive / direct), `SCardReconnect`, `SCardDisconnect` (leave /
reset / unpower / eject), `SCardBeginTransaction/EndTransaction`, `SCardStatus`,
`SCardTransmit` (T=0/T=1 PCI), `SCardControl`, `SCardGetAttrib/SetAttrib`.
`CardMonitor` turns status changes into insert/remove/reader_added/reader_removed callbacks.

## 10. HBCI (`hbci.py`, `ctapi.py`)

HBCI/FinTS banking software uses the 3021 as a **class 1 card terminal** (no keypad/display)
for **DDV** chip cards, normally through **CT-API** (MKT / DIN 66291).

### 10.1 CT-API and CT-BCS

`CT_init(ctn, pn)`, `CT_data(ctn, dad, sad, cmd) -> (rc, dad, sad, response)`, `CT_close(ctn)`.
Addresses: 0 = ICC, 1 = CT, 2 = HOST.  Return codes 0 OK, -1 ERR_INVALID, -8 ERR_CT, -10 ERR_TRANS,
-11 ERR_MEMORY, -127 ERR_HTSI, -128 ERR_HOST.  CT-BCS commands handled by the PC/SC bridge:

| Command | APDU | Response |
|---|---|---|
| RESET CT | `20 11 00 00` | `90 00` |
| RESET ICC | `20 11 01 P2` (P2 00 none / 01 ATR / 02 historical bytes) | data + `90 00` (synchronous) / `90 01` (asynchronous); `64 00` no card |
| REQUEST ICC | `20 12 01 P2 [01 timeout]` | waits for insertion; data + `90 00`/`90 01`; `62 00` timeout |
| GET STATUS (CT) | `20 13 00 46` | `46 len <manufacturer/type/version>` |
| GET STATUS (ICC) | `20 13 00 80` | `80 01 xx` (00 no card, 03 present, 05 present + connected) |
| EJECT ICC | `20 15 01 P2 [01 timeout]` | unpower; optional wait for removal |
| PERFORM/MODIFY VERIFICATION, INPUT, OUTPUT | `20 18/19/16/17` | `6D 00` - class 1 reader has no keypad / display |

`NativeCtApi` wraps a vendor CT-API library (HID's, or any `libctapi*.so`/`.dll`) with the same
Python interface, for software that must go through the vendor library.

### 10.2 DDV card commands (as in hbci4java)

| Purpose | APDU |
|---|---|
| Select DDV type 1 / type 0 | `00 A4 04 0C 09 D2 76 00 00 25 48 42 02 00` / `... 01 00` |
| Card id (EF_ID, SFI 19) | `00 B2 01 CC 00` |
| Bank data (EF_BNK, SFI 1A, 88-byte records) | `00 B2 <n> D4 00`: name[0:20], BLZ[20:24] BCD, comm type[24], address[25:53], [53:55], country[55:58], user id[58:88] |
| Signature counter (EF_SEQ, SFI 1C) | `00 B2 01 E4 00` / `00 DC 01 E4 02 hi lo` |
| Key info | type 0: SELECT `0013`/`0014` + `00 B2 01 04 00`; type 1: `B0 EE 80 <n> 00` |
| VERIFY PIN | `00 20 00 81 08 <2N BCD-PIN padded F>` (format-2 PIN block) |
| MAC (sign) | UPDATE RECORD EF_MAC with hash[8:20]; type 0: `00 DA 01 00 08 hash[0:8]` then `04 B2 01 DC 00` → MAC = response[12:20]; type 1: `08 B2 01 DC 11 BA 0C B4 0A 87 08 <hash[0:8]> 96 01 00 00` → MAC = response[16:24] |
| Session key | 2 × (`00 84 00 00 08` GET CHALLENGE, `00 88 00 8<key> 08 <challenge> 08` INTERNAL AUTHENTICATE) |
| Decrypt session key | 2 × INTERNAL AUTHENTICATE over the 8-byte halves |

The FinTS message layer (dialog initialisation, segments, HTTPS transport) is a banking client's
job; hbci4java, AqBanking and similar can use the 3021 through PC/SC or CT-API without this toolkit.

## 11. Calypso transport cards (`calypso.py`)

Calypso is a transit ticketing standard.  Most Calypso cards are **contactless**
(ISO 14443-B) and cannot be used with the contact-only 3021; **dual-interface**
cards (with a contact plate) work.  The command set is ISO 7816-4 based, so the
free-access read path needs nothing special; writing needs a **Calypso SAM**.

Class byte: `00` (Rev 3.x) or `94` (Rev 2.4 legacy); the toolkit tries both on SELECT.

| Operation | APDU | SAM? |
|---|---|---|
| Select application | `00 A4 04 00 08 <AID> 00` (`1TIC.ICA` = 31 54 49 43 2E 49 43 41); FCI has `C7` serial + `53` startup info | no |
| Select file (LID) | `00 A4 08 00 02 <lid>` | no |
| Read record | `00 B2 <rec> <SFI<<3 \| 04> 00` | no |
| Read records | one READ RECORD per record (portable across layouts) | no |
| Get data | `00 CA <tag>` | no |
| Get challenge | `00 84 00 00 08` | no |
| Open secure session | `00 8A <rec> <SFI<<3 \| key idx> 08 <SAM challenge> 00`; response = card challenge (+ record) | yes |
| Update / write / append record | `00 DC`/`D2`/`E2`, MAC'd by the session | yes |
| Increase / decrease counter | `00 32`/`30 <ctr> <SFI<<3> 03 <amount>` | yes |
| Close secure session | `00 8E 80 00 04 <terminal MAC> 00`; response = card MAC (verified by the SAM) | yes |

Standard transport SFIs: `07` Environment & Holder, `08` Event log, `09` Contracts,
`19` Counters, `1D` Special events, `1E` Contract list.  Record *contents* are
network-specific (Intercode in France, custom elsewhere) and are not decoded.

**The secure session.** A Calypso write is only accepted if it is inside a session
whose MAC is computed by a SAM holding the card's keys.  Flow: the SAM diversifies
on the card serial and issues a challenge -> OPEN SECURE SESSION sends it to the
card -> every command and response is fed to the SAM digest -> CLOSE SECURE SESSION
carries the SAM's terminal MAC, and the card's returned MAC is checked by the SAM.
A wrong key makes the card reject the close (`69 88`); a tampered card makes the SAM
reject authentication.  There is no way to forge this without the keys, by design.

**Byte layout caveat.** The OPEN/CLOSE P1/P2 and the SAM APDUs vary by Calypso
revision and SAM product; the constants at the top of `calypso.py` follow the public
Calypso spec and Eclipse Keyple and are marked to verify against your hardware before
production writes.  The `SimulatedCalypsoCard` + `SimulatedSam` exercise the whole
flow (read, open, update, increase, close, MAC check) in the test suite.

**To build a system for your own vehicles**: buy Calypso Prime cards and a matching
SAM from a Calypso vendor (the SAM is provisioned with your keys), put the SAM in a
second OMNIKEY 3021, and use `PcscSam` / `omnikey3021 calypso write --sam-reader`.
For contactless cards, the same modules apply once you move to a contactless OMNIKEY;
Eclipse Keyple is the reference open-source Calypso stack if you outgrow this.
