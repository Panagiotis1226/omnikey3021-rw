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
