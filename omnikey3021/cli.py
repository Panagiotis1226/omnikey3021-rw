"""Command line interface: ``omnikey3021 <command> ...`` (or ``python -m omnikey3021``)."""

from __future__ import annotations

import argparse
import json
import os
import pickle
import subprocess
import sys
import time
import urllib.request
from typing import Any

from . import pcsc_constants as C
from .apdu import hexstr, parse_hex, transmit_apdu
from .atr import parse_atr
from .errors import CardError, NoCardError, OmnikeyError, VendorError
from .iso7816 import Iso7816Card
from .memorycard import I2C_TYPES, ProtectableMemoryCard, open_memory_card
from .vendor import ReaderConfig, encode_voltage_sequence

PROTOCOLS = {"any": C.SCARD_PROTOCOL_ANY, "t0": C.SCARD_PROTOCOL_T0, "t1": C.SCARD_PROTOCOL_T1, "raw": C.SCARD_PROTOCOL_RAW}


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------
class Session:
    """Owns the reader (real or simulated) and the card channel for one CLI invocation."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.reader: Any = None
        self.channel: Any = None
        self._sim_state_path: str | None = None

    def __enter__(self):
        if self.args.simulate:
            from .simulator import SimulatedIsoCard, SimulatedMemoryCard, SimulatedReader

            self._sim_state_path = self.args.sim_state
            if self._sim_state_path and os.path.exists(self._sim_state_path):
                with open(self._sim_state_path, "rb") as fh:
                    self.reader = pickle.load(fh)
            else:
                from .simulator import SimulatedCalypsoCard, SimulatedDDVCard, SimulatedEmvCard

                card = {"sle4442": lambda: SimulatedMemoryCard(), "iso": lambda: SimulatedIsoCard(),
                        "iso-t0": lambda: SimulatedIsoCard(t0_style=True), "emv": lambda: SimulatedEmvCard(),
                        "hbci": lambda: SimulatedDDVCard(), "calypso": lambda: SimulatedCalypsoCard(), "empty": lambda: None}[self.args.simulate]()
                self.reader = SimulatedReader(card)
        else:
            from .reader import OmnikeyReader

            self.reader = OmnikeyReader(self.args.reader, pattern=self.args.pattern)
        return self

    def __exit__(self, *exc):
        if self.channel is not None:
            try:
                self.channel.disconnect()
            except OmnikeyError:
                pass
        if self.args.simulate and self._sim_state_path:
            with open(self._sim_state_path, "wb") as fh:
                pickle.dump(self.reader, fh)
        if hasattr(self.reader, "close"):
            self.reader.close()

    def connect(self, wait: bool = True):
        if self.channel is None:
            if wait and not self.args.simulate and not self.reader.is_card_present():
                print("Waiting for card...", file=sys.stderr)
                self.reader.wait_for_card(self.args.timeout)
                time.sleep(0.2)
            share = C.SCARD_SHARE_EXCLUSIVE if self.args.exclusive else C.SCARD_SHARE_SHARED
            self.channel = self.reader.connect(PROTOCOLS[self.args.protocol], share)
            self.channel.trace = self.args.trace
        return self.channel

    def connect_direct(self):
        if self.channel is None:
            self.channel = self.reader.connect_direct()
            self.channel.trace = self.args.trace
        return self.channel


def _print_kv(d: dict, indent: str = "  ") -> None:
    width = max((len(k) for k in d), default=0)
    for k, v in d.items():
        print(f"{indent}{k.ljust(width)} : {v}")


def _bytes_arg(text: str) -> bytes:
    """Accept hex ("41 42"), "str:ABC" or "@file"."""
    if text.startswith("str:"):
        return text[4:].encode("utf-8")
    if text.startswith("@"):
        with open(text[1:], "rb") as fh:
            return fh.read()
    return parse_hex(text)


def _hexdump(data: bytes, base: int = 0) -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        hexpart = " ".join(f"{b:02X}" for b in chunk).ljust(47)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + off:04X}  {hexpart}  {text}")
    return "\n".join(lines)


def _psc(text: str | None) -> bytes | None:
    return parse_hex(text) if text else None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_readers(args):
    if args.simulate:
        from .simulator import SimulatedReader

        print(SimulatedReader.name)
        return 0
    from .reader import OmnikeyReader

    if args.groups:
        from .pcsc import Context

        with Context() as ctx:
            for g in ctx.list_reader_groups():
                print(g)
        return 0
    readers = OmnikeyReader.list(args.pattern, all_readers=args.all)
    if not readers:
        print("No " + ("" if args.all else "OMNIKEY ") + "readers found.", file=sys.stderr)
        return 1
    for r in readers:
        print(r)
    return 0


def cmd_info(args):
    with Session(args) as s:
        have_card = s.reader.is_card_present()
        ch = s.connect() if have_card else s.connect_direct()
        print(f"Reader: {s.reader.name}")
        if have_card:
            atr = parse_atr(ch.atr)
            print(f"Card present, protocol {getattr(ch, 'protocol_name', ch.protocol)}")
            for line in atr.describe():
                print("  " + line)
        else:
            print("No card inserted (reader queried through CCID escape).")
        print("PC/SC attributes:")
        _print_kv(ch.attributes() or {"(none)": "driver exposes no attributes"})
        feats = ch.features()
        print("PC/SC part 10 features:")
        if feats:
            _print_kv({f.name: f"control code 0x{f.control_code:08X}" for f in feats.values()})
        else:
            print("  (none advertised)")
        props = ch.tlv_properties() if hasattr(ch, "tlv_properties") else {}
        if props:
            print("PC/SC part 10 TLV properties (CCID):")
            _print_kv({k: str(v) for k, v in props.items()})
        fw = ch.legacy_firmware_version()
        if fw:
            print(f"Legacy firmware version (CM_IOCTL_GET_FW_VERSION): {hexstr(fw)}")
        cfg = ReaderConfig(ch, via_control=not have_card)
        try:
            print("Reader capabilities (vendor API):")
            _print_kv({k: str(v) for k, v in cfg.capabilities().items()})
            print("Contact slot configuration:")
            _print_kv(cfg.slot_configuration())
        except OmnikeyError as exc:
            print(f"  vendor API not available: {exc}")
            if not have_card:
                print("  (Windows: enable EscapeCommandEnable in the registry, see docs/PROTOCOL_REFERENCE.md)")
    return 0


def cmd_wait(args):
    with Session(args) as s:
        if not args.simulate:
            print("Waiting for card...", file=sys.stderr)
            s.reader.wait_for_card(args.timeout)
        ch = s.connect()
        for line in parse_atr(ch.atr).describe():
            print(line)
        print(f"Protocol: {getattr(ch, 'protocol_name', ch.protocol)}")
    return 0


def cmd_atr(args):
    if args.hex:
        atr = parse_atr(parse_hex(" ".join(args.hex)))
    else:
        with Session(args) as s:
            atr = parse_atr(s.connect().atr)
    for line in atr.describe():
        print(line)
    if args.emv:
        issues = atr.emv_compliance()
        print("EMV Book 1 ATR compliance: " + ("OK" if not issues else "NOT compliant"))
        for i in issues:
            print(f"  - {i}")
        return 0 if not issues else 3
    return 0


def cmd_apdu(args):
    with Session(args) as s:
        ch = s.connect()
        rc = 0
        for text in args.apdus:
            raw = parse_hex(text)
            resp = transmit_apdu(ch.transmit, raw, auto_get_response=not args.no_auto)
            print(f">> {hexstr(raw)}")
            if resp.data:
                print(f"<< {hexstr(resp.data)}")
            print(f"SW {resp.sw:04X}  {resp.description}")
            if not resp.ok:
                rc = 2
    return rc


def cmd_script(args):
    with Session(args) as s:
        ch = s.connect()
        expect: int | None = None
        rc = 0
        with open(args.file) as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                low = line.lower()
                if low.startswith("expect "):
                    expect = int(line.split()[1], 16)
                    continue
                if low.startswith("sleep "):
                    time.sleep(float(line.split()[1]))
                    continue
                if low == "reset":
                    ch.reconnect(True)
                    print("-- reset")
                    continue
                raw = parse_hex(line)
                resp = transmit_apdu(ch.transmit, raw)
                print(f"{lineno:3}: >> {hexstr(raw)}")
                if resp.data:
                    print(f"     << {hexstr(resp.data)}")
                print(f"     SW {resp.sw:04X}  {resp.description}")
                if expect is not None and resp.sw != expect:
                    print(f"     EXPECTED {expect:04X} - stopping")
                    rc = 2
                    if not args.keep_going:
                        break
                expect = None
    return rc


# -- ISO 7816 -------------------------------------------------------------------------------------
def _iso(args, s: Session) -> Iso7816Card:
    ch = s.connect()
    iso = Iso7816Card(ch, cla=args.cla, extended=args.extended)
    if getattr(args, "aid", None):
        iso.select_aid(parse_hex(args.aid), return_fci=False)
    if getattr(args, "path", None):
        iso.select_path(parse_hex(args.path))
    elif getattr(args, "fid", None) is not None:
        iso.select_fid(int(args.fid, 16), p2=0x0C)
    if getattr(args, "pin", None):
        iso.verify(args.pin, reference=int(args.pin_ref, 16))
    return iso


def cmd_iso_select(args):
    with Session(args) as s:
        iso = Iso7816Card(s.connect(), cla=args.cla, extended=args.extended)
        if args.mf:
            fci = iso.select_mf()
        elif args.aid:
            fci = iso.select_aid(parse_hex(args.aid))
        elif args.path:
            fci = iso.select_path(parse_hex(args.path))
        elif args.fid is not None:
            fci = iso.select_fid(int(args.fid, 16))
        else:
            print("specify --mf, --fid, --aid or --path", file=sys.stderr)
            return 2
        for line in fci.describe():
            print(line)
    return 0


def cmd_iso_read(args):
    with Session(args) as s:
        iso = _iso(args, s)
        data = iso.read_binary(args.offset, args.length, sfi=args.sfi)
        if args.out:
            with open(args.out, "wb") as fh:
                fh.write(data)
            print(f"{len(data)} bytes written to {args.out}")
        else:
            print(_hexdump(data, args.offset))
    return 0


def cmd_iso_write(args):
    with Session(args) as s:
        iso = _iso(args, s)
        data = _bytes_arg(args.data)
        iso.update_binary(args.offset, data, sfi=args.sfi)
        print(f"{len(data)} bytes written at offset {args.offset}")
        if args.verify:
            back = iso.read_binary(args.offset, len(data))
            print("Verify: " + ("OK" if back == data else "MISMATCH"))
            return 0 if back == data else 2
    return 0


def cmd_iso_records(args):
    with Session(args) as s:
        iso = _iso(args, s)
        if args.number:
            print(hexstr(iso.read_record(args.number, sfi=args.sfi)))
        else:
            for i, rec in enumerate(iso.read_all_records(sfi=args.sfi), 1):
                print(f"{i:3}: {hexstr(rec)}")
    return 0


def cmd_iso_verify(args):
    with Session(args) as s:
        iso = Iso7816Card(s.connect(), cla=args.cla)
        if args.aid:
            iso.select_aid(parse_hex(args.aid), return_fci=False)
        if args.pin is None:
            tries = iso.verify_retries(int(args.pin_ref, 16))
            print("PIN not required / already verified" if tries is None else f"{tries} tries remaining")
            return 0
        try:
            iso.verify(args.pin, reference=int(args.pin_ref, 16))
            print("PIN verified")
        except CardError as exc:
            print(f"PIN rejected: {exc.description}")
            return 2
    return 0


def cmd_iso_change_pin(args):
    with Session(args) as s:
        iso = Iso7816Card(s.connect(), cla=args.cla)
        if args.aid:
            iso.select_aid(parse_hex(args.aid), return_fci=False)
        iso.change_reference_data(args.old, args.new, reference=int(args.pin_ref, 16))
        print("PIN changed")
    return 0


def cmd_iso_challenge(args):
    with Session(args) as s:
        iso = Iso7816Card(s.connect(), cla=args.cla)
        print(hexstr(iso.get_challenge(args.length)))
    return 0


def cmd_iso_getdata(args):
    with Session(args) as s:
        iso = _iso(args, s)
        print(hexstr(iso.get_data(int(args.tag, 16))))
    return 0


# -- memory cards --------------------------------------------------------------------------------------
def _mem(args, s: Session):
    ch = s.connect()
    kwargs = {}
    if args.kind == "i2c" or (args.kind is None and getattr(args, "i2c_type", None)):
        args.kind = "i2c"
        if getattr(args, "i2c_type", None):
            kwargs["card_type"] = args.i2c_type
        else:
            kwargs.update(page_size=args.page_size, address_bytes=args.address_bytes, memory_size=args.memory_size)
    card = open_memory_card(ch, args.kind, **kwargs)
    if getattr(args, "psc", None) and isinstance(card, ProtectableMemoryCard):
        card.verify_psc(parse_hex(args.psc))
    return card


def cmd_mem_info(args):
    with Session(args) as s:
        card = _mem(args, s)
        for line in parse_atr(s.channel.atr).describe():
            print(line)
        _print_kv(card.info(), "")
    return 0


def cmd_mem_read(args):
    with Session(args) as s:
        card = _mem(args, s)
        data = card.read(args.addr, args.length)
        if args.out:
            with open(args.out, "wb") as fh:
                fh.write(data)
            print(f"{len(data)} bytes written to {args.out}")
        else:
            print(_hexdump(data, args.addr))
    return 0


def cmd_mem_write(args):
    with Session(args) as s:
        card = _mem(args, s)
        data = _bytes_arg(args.data)
        card.write(args.addr, data, verify=args.verify)
        print(f"{len(data)} bytes written at address {args.addr}" + (" (verified)" if args.verify else ""))
    return 0


def cmd_mem_verify(args):
    with Session(args) as s:
        card = open_memory_card(s.connect(), args.kind)
        if not isinstance(card, ProtectableMemoryCard):
            print("this card type has no PSC", file=sys.stderr)
            return 2
        try:
            card.verify_psc(parse_hex(args.psc_value))
            print("PSC accepted; card is unlocked for writing until power off")
        except CardError as exc:
            print(f"PSC rejected: {exc.description}")
            return 2
    return 0


def cmd_mem_change_psc(args):
    with Session(args) as s:
        card = open_memory_card(s.connect(), args.kind)
        if not isinstance(card, ProtectableMemoryCard):
            print("this card type has no PSC", file=sys.stderr)
            return 2
        card.change_psc(parse_hex(args.old), parse_hex(args.new))
        print("PSC changed")
    return 0


def cmd_mem_protection(args):
    with Session(args) as s:
        card = open_memory_card(s.connect(), args.kind)
        if not isinstance(card, ProtectableMemoryCard):
            print("this card type has no protection bits", file=sys.stderr)
            return 2
        length = args.length or (32 if card.kind.name == "SLE4442" else 256)
        bits = card.read_protection_bits(args.addr, length)
        for off in range(0, len(bits), 32):
            row = bits[off : off + 32]
            print(f"{args.addr + off:04X}  " + "".join("P" if b else "." for b in row))
        print(f"{sum(bits)} of {len(bits)} bytes protected (P = write protected, irreversible)")
    return 0


def cmd_mem_protect(args):
    with Session(args) as s:
        card = _mem(args, s)
        if not isinstance(card, ProtectableMemoryCard):
            print("this card type has no protection bits", file=sys.stderr)
            return 2
        data = _bytes_arg(args.data) if args.data else card.read(args.addr, args.length)
        if not args.yes:
            print(f"About to IRREVERSIBLY protect {len(data)} byte(s) at address {args.addr}. Re-run with --yes.")
            return 2
        card.protect(args.addr, data)
        print(f"{len(data)} byte(s) protected")
    return 0


def cmd_i2c_types(args):
    for t in I2C_TYPES.values():
        print(f"0x{t.code:02X}  {t.name:10} page {t.page_size:3}  address bytes {t.address_bytes}  size {t.memory_size}")
    return 0


# -- reader configuration ---------------------------------------------------------------------------------
def _cfg(args, s: Session) -> ReaderConfig:
    have_card = s.reader.is_card_present()
    ch = s.connect() if have_card else s.connect_direct()
    return ReaderConfig(ch, via_control=not have_card)


def cmd_reader_caps(args):
    with Session(args) as s:
        _print_kv({k: str(v) for k, v in _cfg(args, s).capabilities().items()}, "")
    return 0


def cmd_reader_slot(args):
    with Session(args) as s:
        cfg = _cfg(args, s)
        changed = False
        if args.exchange_level:
            level = {"tpdu": 1, "apdu": 2, "extended": 4}[args.exchange_level]
            cfg.set_exchange_level(level)
            changed = True
        if args.voltage is not None:
            seq = [v for v in args.voltage.split(",") if v] if args.voltage.lower() != "auto" else []
            cfg.set_voltage_sequence(encode_voltage_sequence(seq))
            changed = True
        if args.mode:
            cfg.set_operating_mode({"iso": 0, "emvco": 1}[args.mode])
            changed = True
        _print_kv(cfg.slot_configuration(), "")
        if changed:
            print("Settings stored; restart (re-plug or `reader reboot`) the reader to apply them.")
    return 0


def cmd_reader_eeprom(args):
    with Session(args) as s:
        cfg = _cfg(args, s)
        if args.data is None:
            data = cfg.read_eeprom(args.offset, args.length)
            print(_hexdump(data, args.offset))
        else:
            data = _bytes_arg(args.data)
            cfg.write_eeprom(args.offset, data)
            print(f"{len(data)} bytes written to user EEPROM at offset {args.offset}")
    return 0


def cmd_reader_reboot(args):
    with Session(args) as s:
        _cfg(args, s).reboot()
        print("Reboot command sent")
    return 0


def cmd_reader_factory_reset(args):
    if not args.yes:
        print("This discards all custom reader settings. Re-run with --yes.")
        return 2
    with Session(args) as s:
        _cfg(args, s).restore_factory_defaults()
        print("Factory defaults restored; reboot the reader")
    return 0


def cmd_reader_escape(args):
    with Session(args) as s:
        ch = s.connect() if s.reader.is_card_present() else s.connect_direct()
        resp = ch.escape(parse_hex(" ".join(args.hex)))
        print(hexstr(resp))
    return 0


# -- access control ------------------------------------------------------------------------------------------
def _access(args):
    from .access import AccessController, AccessStore, load_or_create_key

    store = AccessStore(args.db)
    site = store.get_meta("site_code")
    if site is None:
        if args.site_code is None:
            raise SystemExit("access system not initialised: run `omnikey3021 access init --site-code N` first")
        store.set_meta("site_code", str(args.site_code))
        site = str(args.site_code)
    key = load_or_create_key(args.key_file, create=True)
    ctl = AccessController(store, key, int(site), mem_offset=args.mem_offset, iso_fid=int(args.iso_fid, 16),
                           iso_aid=parse_hex(args.iso_aid) if args.iso_aid else None,
                           iso_pin=args.iso_pin.encode() if args.iso_pin else None,
                           iso_challenge=args.iso_challenge, memory_kind=args.kind)
    return store, ctl


def cmd_access_init(args):
    from .access import AccessStore, load_or_create_key

    store = AccessStore(args.db)
    store.set_meta("site_code", str(args.site_code))
    key = load_or_create_key(args.key_file, create=True)
    print(f"Database: {args.db}\nSite key: {args.key_file} ({len(key)} bytes) - back this file up and keep it secret\n"
          f"Site code: {args.site_code}")
    return 0


def cmd_access_holder(args):
    store, _ = _access(args)
    if args.action == "add":
        h = store.add_holder(args.name, args.level, args.note or "")
        print(f"holder #{h.id} {h.name} level {h.level}")
    elif args.action == "list":
        for h in store.holders():
            print(f"#{h.id:<4} {h.name:24} level {h.level:<3} {'active' if h.active else 'DISABLED'}")
    elif args.action in ("enable", "disable"):
        store.set_holder_active(int(args.name), args.action == "enable")
        print(f"holder #{args.name} {args.action}d")
    return 0


def _resolve_holder(store, text: str):
    h = store.get_holder(int(text)) if text.isdigit() else store.find_holder(text)
    if h is None:
        raise SystemExit(f"holder {text!r} not found (add with `access holder add`)")
    return h


def cmd_access_enroll(args):
    store, ctl = _access(args)
    holder = _resolve_holder(store, args.holder)
    expires = time.time() + args.expires_days * 86400 if args.expires_days else 0
    with Session(args) as s:
        ch = s.connect()
        cred, rec = ctl.enroll(ch, holder, card_id=args.card_id, expires=expires, access_level=args.level,
                               psc=_psc(args.psc), note=args.note or "", protect_manufacturer_area=args.protect_binding)
        print(f"Enrolled {holder.name}: card id {cred.card_id}, uid {rec.uid}, kind {rec.kind}")
        _print_kv(cred.describe())
    return 0


def _print_decision(d) -> None:
    print(d.summary())
    if d.detail:
        print(f"  detail: {d.detail}")
    if d.credential:
        _print_kv(d.credential.describe())


def cmd_access_check(args):
    _, ctl = _access(args)
    with Session(args) as s:
        d = ctl.check(s.connect())
        _print_decision(d)
    return 0 if d.granted else 3


def cmd_access_monitor(args):
    _, ctl = _access(args)

    def on_decision(d):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{stamp}] {d.summary()}", flush=True)
        payload = {"granted": d.granted, "reason": d.reason, "card_id": d.credential.card_id if d.credential else None,
                   "holder": d.holder.name if d.holder else None, "level": d.credential.access_level if d.credential else None,
                   "uid": d.uid, "kind": d.kind, "ts": time.time()}
        if args.exec and (d.granted or args.exec_on_deny):
            cmd = args.exec.format(**{k: ("" if v is None else v) for k, v in payload.items()})
            try:
                subprocess.run(cmd, shell=True, timeout=30, check=False)
            except Exception as exc:  # noqa: BLE001
                print(f"  exec failed: {exc}", file=sys.stderr)
        if args.webhook:
            try:
                req = urllib.request.Request(args.webhook, json.dumps(payload).encode(), {"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=10).read()
            except Exception as exc:  # noqa: BLE001
                print(f"  webhook failed: {exc}", file=sys.stderr)

    with Session(args) as s:
        if args.simulate:
            d = ctl.check(s.connect())
            on_decision(d)
            return 0
        print(f"Monitoring {s.reader.name} - Ctrl+C to stop", file=sys.stderr)
        try:
            ctl.monitor(s.reader, on_decision, once=args.once)
        except KeyboardInterrupt:
            print("stopped", file=sys.stderr)
    return 0


def cmd_access_revoke(args):
    store, _ = _access(args)
    ok = store.revoke_card(args.card_id, not args.restore)
    print(("restored" if args.restore else "revoked") if ok else "card id not found")
    return 0 if ok else 1


def cmd_access_cards(args):
    store, _ = _access(args)
    for c in store.cards():
        h = store.get_holder(c.holder_id) if c.holder_id else None
        exp = time.strftime("%Y-%m-%d", time.localtime(c.expires)) if c.expires else "never"
        print(f"card {c.card_id:<5} {h.name if h else '?':20} {c.kind:18} expires {exp:10} {'REVOKED' if c.revoked else 'active'}  uid {c.uid}")
    return 0


def cmd_access_log(args):
    store, _ = _access(args)
    for e in reversed(store.events(args.limit)):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["ts"]))
        print(f"{stamp} {'GRANT' if e['granted'] else 'DENY '} card={e['card_id'] or '-':<5} {e['holder'] or '-':16} {e['reason']} {e['detail']}")
    return 0


def cmd_access_erase(args):
    _, ctl = _access(args)
    with Session(args) as s:
        ctl.erase(s.connect(), psc=_psc(args.psc))
        print("credential block erased")
    return 0


def cmd_access_schedule(args):
    store, _ = _access(args)
    days_map = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
    if args.action == "add":
        if args.days == "all":
            days = list(range(7))
        elif "-" in args.days and "," not in args.days:
            a, b = args.days.split("-")
            days = list(range(days_map[a[:3].lower()], days_map[b[:3].lower()] + 1))
        else:
            days = [days_map[d.strip()[:3].lower()] for d in args.days.split(",")]
        h1, m1 = map(int, args.start.split(":"))
        h2, m2 = map(int, args.end.split(":"))
        store.add_schedule(args.level, days, h1 * 60 + m1, h2 * 60 + m2)
        print("schedule added")
    elif args.action == "clear":
        store.clear_schedules(args.level)
        print("schedules cleared")
    else:
        names = list(days_map)
        for level, dow, start, end in store.schedules():
            print(f"level {level}: {names[dow]} {start // 60:02d}:{start % 60:02d}-{end // 60:02d}:{end % 60:02d}")
        if not store.schedules():
            print("(no schedules: all levels allowed at all times)")
    return 0



# -- EMV -------------------------------------------------------------------------------------------
def _emv(args, s: Session):
    from .emv import EmvCard, TerminalData

    term = TerminalData(country_code=int(args.country, 16), currency_code=int(args.currency, 16), amount=args.amount)
    return EmvCard(s.connect(), term)


def cmd_emv_apps(args):
    with Session(args) as s:
        emv = _emv(args, s)
        apps = emv.list_applications(contactless_pse=False, probe=not args.no_probe)
        if not apps:
            print("no EMV application found")
            return 3
        for a in apps:
            prio = f" priority {a.priority}" if a.priority is not None else ""
            print(f"{a.aid.hex().upper():24} {a.label or '-':20} {a.scheme}{prio}")
    return 0


def cmd_emv_read(args):
    with Session(args) as s:
        emv = _emv(args, s)
        if args.aid:
            aid = parse_hex(args.aid)
        else:
            apps = emv.list_applications(probe=not args.no_probe)
            if not apps:
                print("no EMV application found")
                return 3
            aid = apps[0].aid
        data = emv.read_application(aid)
        for line in data.describe(mask_pan=not args.unmask):
            print(line)
        atc = emv.transaction_counter()
        if atc is not None:
            print(f"  ATC (9F36): {atc}")
        ptc = emv.pin_try_counter()
        if ptc is not None:
            print(f"  PIN try counter (9F17): {ptc}")
        last = emv.last_online_atc()
        if last is not None:
            print(f"  Last online ATC (9F13): {last}")
    return 0


def cmd_emv_log(args):
    with Session(args) as s:
        emv = _emv(args, s)
        aid = parse_hex(args.aid) if args.aid else (emv.list_applications(probe=not args.no_probe) or [None])[0]
        if aid is None:
            print("no EMV application found")
            return 3
        emv.select_application(aid if isinstance(aid, bytes) else aid.aid)
        rows = emv.transaction_log()
        if not rows:
            print("card exposes no transaction log")
            return 3
        for i, row in enumerate(rows, 1):
            print(f"{i:3}: " + "; ".join(f"{k}={v}" for k, v in row.items()))
    return 0


# -- HBCI (DDV) --------------------------------------------------------------------------------------
def _hbci(args, s: Session):
    from .hbci import DDVCard

    card = DDVCard(s.connect())
    card.select()
    if getattr(args, "pin", None):
        card.verify_pin(args.pin)
    return card


def cmd_hbci_info(args):
    with Session(args) as s:
        card = _hbci(args, s)
        _print_kv(card.info(), "")
        tries = card.pin_tries_remaining()
        if tries is not None:
            print(f"PIN tries remaining : {tries}")
    return 0


def cmd_hbci_pin(args):
    with Session(args) as s:
        card = _hbci(args, s)
        if args.pin_value is None:
            print(f"PIN tries remaining: {card.pin_tries_remaining()}")
            return 0
        try:
            card.verify_pin(args.pin_value)
            print("PIN accepted")
        except CardError as exc:
            print(f"PIN rejected: {exc.description}")
            return 2
    return 0


def cmd_hbci_sigid(args):
    with Session(args) as s:
        card = _hbci(args, s)
        if args.set is not None:
            card.set_signature_counter(args.set)
        print(f"signature counter: {card.signature_counter()}")
    return 0


def cmd_hbci_sign(args):
    with Session(args) as s:
        card = _hbci(args, s)
        mac = card.sign(parse_hex(args.hash20))
        print(f"MAC: {mac.hex().upper()}")
    return 0


def cmd_hbci_keys(args):
    with Session(args) as s:
        card = _hbci(args, s)
        for k in card.key_data():
            print(k.describe())
        if args.derive is not None:
            plain, enc = card.get_encryption_keys(args.derive)
            print(f"session key (plain): {plain.hex().upper()}")
            print(f"session key (encrypted by card key {args.derive}): {enc.hex().upper()}")
    return 0


def cmd_hbci_bank(args):
    with Session(args) as s:
        card = _hbci(args, s)
        if args.set_blz or args.set_user or args.set_host:
            from .hbci import BankData

            bd = card.bank_data(args.record - 1) or BankData(args.record, "", "0" * 8, 2, "", "", "280", "")
            if args.set_blz:
                bd.blz = args.set_blz
            if args.set_user:
                bd.user_id = args.set_user
            if args.set_host:
                bd.comm_addr = args.set_host
                bd.comm_type = 2
            if args.set_name:
                bd.shortname = args.set_name
            card.write_bank_data(args.record - 1, bd)
            print("bank record updated")
        for bd in card.all_bank_data():
            _print_kv(bd.describe(), "")
            print()
    return 0


# -- CCID / PC-SC extras ------------------------------------------------------------------------------
def cmd_ccid(args):
    from .ccid import HID_VENDOR_ID, find_usb_ccid_devices

    rc = 0
    if not args.simulate:
        devs = find_usb_ccid_devices(None if args.all_usb else HID_VENDOR_ID)
        if devs:
            for d in devs:
                print(f"USB {d.vendor_id:04X}:{d.product_id:04X} {d.manufacturer} {d.product} ({d.model})  serial {d.serial or '-'}  "
                      f"firmware bcdDevice {d.bcd_device}  USB {d.usb_version} {d.speed_mbps} Mbit/s  [{d.sysfs_path}]")
                if d.descriptor:
                    print("  CCID class descriptor:")
                    _print_kv(d.descriptor.describe(), "    ")
                for w in d.warnings:
                    print(f"  warning: {w}")
        else:
            print("No USB CCID device found via sysfs (Linux only); showing PC/SC view instead.")
    with Session(args) as s:
        ch = s.connect() if s.reader.is_card_present() else s.connect_direct()
        props = ch.tlv_properties() if hasattr(ch, "tlv_properties") else {}
        print("PC/SC part 10 TLV properties:")
        _print_kv({k: str(v) for k, v in props.items()} or {"(none)": "reader/driver does not advertise GET_TLV_PROPERTIES"})
        feats = ch.features()
        print("PC/SC part 10 features:")
        _print_kv({f.name: f"0x{f.control_code:08X}" for f in feats.values()} or {"(none)": "-"})
        print("PC/SC attributes:")
        _print_kv(ch.attributes() or {"(none)": "-"})
    return rc


def cmd_monitor(args):
    if args.simulate:
        with Session(args) as s:
            if s.reader.is_card_present():
                print(f"insert  {s.reader.name}  ATR {s.reader.card.atr.hex(' ').upper()}")
            else:
                print(f"empty   {s.reader.name}")
        return 0
    from .pcsc import CardMonitor

    def cb(event, reader, atr):
        stamp = time.strftime("%H:%M:%S")
        extra = f"  ATR {atr.hex(' ').upper()}" if atr else ""
        print(f"[{stamp}] {event:14} {reader}{extra}", flush=True)

    mon = CardMonitor(cb, [args.reader] if args.reader else None, pattern=args.pattern, hotplug=not args.no_hotplug)
    print("Monitoring card events - Ctrl+C to stop", file=sys.stderr)
    try:
        mon.loop()
    except KeyboardInterrupt:
        mon.stop()
    return 0


def cmd_ctapi(args):
    from . import ctapi as ct

    if args.simulate:
        sess = Session(args).__enter__()
        api = ct.PcscCtApi(reader_factory=lambda pn: sess.reader)
    elif args.library:
        api = ct.NativeCtApi(args.library)
    else:
        api = ct.PcscCtApi(args.reader, args.pattern)
    rc = api.CT_init(args.ctn, args.port)
    print(f"CT_init({args.ctn}, {args.port}) -> {ct.RETURN_CODE_NAMES.get(rc, rc)}")
    if rc != ct.OK:
        return 1
    dad = {"ct": ct.CT, "icc": ct.ICC1}[args.dad]
    result = 0
    for text in args.commands:
        cmd = parse_hex(text)
        rc, _, _, resp = api.CT_data(args.ctn, dad, ct.HOST, cmd)
        print(f">> {hexstr(cmd)}  (dad={args.dad})")
        print(f"<< {hexstr(resp)}  rc={ct.RETURN_CODE_NAMES.get(rc, rc)}")
        if rc != ct.OK:
            result = 2
    api.CT_close(args.ctn)
    return result



# -- Calypso -------------------------------------------------------------------------------------
def _calypso(args, s: Session):
    from .calypso import AID_1TIC_ICA, CalypsoCard

    card = CalypsoCard(s.connect(), revision=args.revision)
    aid = parse_hex(args.aid) if args.aid else AID_1TIC_ICA
    if getattr(args, "implicit", False):
        card.implicit_identity()
        return card
    ident = card.select_application(aid, required=False)
    if ident is None:
        print("SELECT by AID unsupported; using implicit selection (reading files directly by SFI).",
              file=sys.stderr)
        card.implicit_identity()
    return card


def cmd_calypso_info(args):
    with Session(args) as s:
        card = _calypso(args, s)
        for line in (card.identity.describe() if card.identity else []):
            print(line)
        print("Files:")
        _print_kv({f"EF {k:02X}": f"{len(v)} record(s) x {len(v[0].data)} bytes" for k, v in card.dump().items()}, "  ")
    return 0


def cmd_calypso_dump(args):
    with Session(args) as s:
        card = _calypso(args, s)
        for line in (card.identity.describe() if card.identity else []):
            print(line)
        for sfi, recs in card.dump().items():
            from .calypso import STANDARD_SFIS

            print(f"\nEF {sfi:02X} ({STANDARD_SFIS.get(sfi, 'file')}):")
            for r in recs:
                print(f"  rec {r.number:2}: {r.data.hex(' ').upper()}")
    return 0


def cmd_calypso_read(args):
    with Session(args) as s:
        card = _calypso(args, s)
        if args.record:
            print(card.read_record(args.sfi, args.record).hex(" ").upper())
        else:
            for r in card.read_records(args.sfi):
                print(f"rec {r.number:2}: {r.data.hex(' ').upper()}")
    return 0


def cmd_calypso_probe(args):
    """Send a small matrix of selection/read commands, resetting the card between each,
    and report which the card answers. Use this to work out how an unknown transport
    card wants to be addressed."""
    import time as _t

    from .apdu import ResponseAPDU

    probes = [
        ("SELECT MF (00 A4 00 00 3F00)", "00 A4 00 00 02 3F 00"),
        ("SELECT AID 1TIC.ICA CLA 00 Le", "00 A4 04 00 08 31 54 49 43 2E 49 43 41 00"),
        ("SELECT AID 1TIC.ICA CLA 00 no Le", "00 A4 04 00 08 31 54 49 43 2E 49 43 41"),
        ("SELECT AID 1TIC.ICA CLA 94", "94 A4 04 00 08 31 54 49 43 2E 49 43 41 00"),
        ("SELECT AID CLA 00 P2=0C", "00 A4 04 0C 08 31 54 49 43 2E 49 43 41"),
        ("GET CHALLENGE (00 84 00 00 08)", "00 84 00 00 08"),
        ("READ REC sfi7 CLA 00 (00 B2 01 3C 00)", "00 B2 01 3C 00"),
        ("READ REC sfi7 CLA 94 (94 B2 01 3C 00)", "94 B2 01 3C 00"),
        ("READ REC sfi1 CLA 00 (00 B2 01 0C 00)", "00 B2 01 0C 00"),
        ("SELECT EF 2001 by LID (00 A4 08 00 2001)", "00 A4 08 00 02 20 01"),
        ("SELECT EF 2001 CLA 94", "94 A4 08 00 02 20 01"),
    ]
    with Session(args) as s:
        for label, hexcmd in probes:
            try:
                s.channel.reconnect(reset=True)
            except Exception:
                pass
            raw = parse_hex(hexcmd)
            t0 = _t.perf_counter()
            try:
                resp = s.connect().transmit(raw)
                dt = (_t.perf_counter() - t0) * 1000
                if len(resp) >= 2:
                    r = ResponseAPDU.from_bytes(resp)
                    tag = "OK " if r.ok else ("warn" if r.warning else "err ")
                    data = f" data={r.data.hex(' ').upper()}" if r.data else ""
                    print(f"[{tag}] {label:44} SW {r.sw:04X} ({dt:5.0f} ms){data}")
                else:
                    print(f"[EMPTY] {label:44} {len(resp)} bytes ({dt:5.0f} ms)")
            except Exception as exc:  # noqa: BLE001
                dt = (_t.perf_counter() - t0) * 1000
                print(f"[FAIL ] {label:44} {type(exc).__name__}: {exc} ({dt:5.0f} ms)")
        # sequence phase: select then read in the SAME session (the real read flow)
        print("--- sequence (no reset between the two commands) ---")
        sequences = [
            ("CLA00 SELECT AID then READ sfi7", "00 A4 04 00 08 31 54 49 43 2E 49 43 41 00", "00 B2 01 3C 00"),
            ("CLA94 SELECT AID then READ sfi7", "94 A4 04 00 08 31 54 49 43 2E 49 43 41 00", "94 B2 01 3C 00"),
            ("SELECT MF then READ sfi7 CLA00", "00 A4 00 00 02 3F 00", "00 B2 01 3C 00"),
        ]
        for label, sel, read in sequences:
            try:
                s.channel.reconnect(reset=True)
            except Exception:
                pass
            try:
                r1 = s.connect().transmit(parse_hex(sel))
                s1 = ResponseAPDU.from_bytes(r1).sw if len(r1) >= 2 else None
                r2 = s.connect().transmit(parse_hex(read))
                if len(r2) >= 2:
                    rr = ResponseAPDU.from_bytes(r2)
                    print(f"  {label:36} select SW {s1:04X} -> read SW {rr.sw:04X}"
                          + (f" data={rr.data.hex(' ').upper()}" if rr.data else ""))
                else:
                    print(f"  {label:36} select SW {s1 and format(s1,'04X')} -> read EMPTY ({len(r2)} bytes)")
            except Exception as exc:  # noqa: BLE001
                print(f"  {label:36} {type(exc).__name__}: {exc}")
    return 0


def _open_sam(args):
    """Open the SAM in a second reader and return a PcscSam (real hardware only)."""
    from .calypso import PcscSam
    from .reader import OmnikeyReader

    reader = OmnikeyReader(args.sam_reader) if args.sam_reader else None
    if reader is None:
        names = [n for n in OmnikeyReader.list() if n != args.reader]
        if not names:
            raise SystemExit("no SAM reader found; pass --sam-reader NAME (the reader holding the Calypso SAM)")
        reader = OmnikeyReader(names[0])
    sam_session = reader.connect()
    return PcscSam(sam_session)


def cmd_calypso_write(args):
    if args.simulate:
        print("writing needs a real Calypso SAM; --simulate has no SAM. Use the Python API with SimulatedSam for a dry run.")
        return 2
    with Session(args) as s:
        card = _calypso(args, s)
        sam = _open_sam(args)
        card.open_secure_session(sam, key_index=args.key_index)
        try:
            data = _bytes_arg(args.data)
            if args.append:
                card.append_record(args.sfi, data)
                print(f"appended {len(data)} bytes to EF {args.sfi:02X}")
            else:
                card.update_record(args.sfi, args.record, data)
                print(f"updated EF {args.sfi:02X} record {args.record}")
            card.close_secure_session()
            print("secure session closed and authenticated by the SAM")
        except Exception:
            card.abort_secure_session()
            raise
    return 0


def cmd_calypso_counter(args):
    if args.simulate:
        print("counter changes need a real Calypso SAM; --simulate has no SAM.")
        return 2
    with Session(args) as s:
        card = _calypso(args, s)
        sam = _open_sam(args)
        card.open_secure_session(sam, key_index=args.key_index)
        try:
            if args.decrease:
                val = card.decrease_counter(args.sfi, args.counter, args.decrease)
                print(f"counter {args.counter} decreased to {int.from_bytes(val, 'big')}")
            elif args.increase:
                val = card.increase_counter(args.sfi, args.counter, args.increase)
                print(f"counter {args.counter} increased to {int.from_bytes(val, 'big')}")
            card.close_secure_session()
            print("secure session closed and authenticated by the SAM")
        except Exception:
            card.abort_secure_session()
            raise
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="omnikey3021", description="Read/write smart cards with the HID OMNIKEY 3021.")
    p.add_argument("--reader", help="exact PC/SC reader name (default: first OMNIKEY reader)")
    p.add_argument("--pattern", help="substring used to pick the reader (default 'omnikey')")
    p.add_argument("--protocol", choices=PROTOCOLS, default="any", help="force T=0 / T=1 (default: card decides)")
    p.add_argument("--timeout", type=float, default=None, help="seconds to wait for a card (default: forever)")
    p.add_argument("--trace", action="store_true", help="print every APDU exchanged")
    p.add_argument("--exclusive", action="store_true", help="connect with SCARD_SHARE_EXCLUSIVE")
    p.add_argument("--simulate", choices=["sle4442", "iso", "iso-t0", "emv", "hbci", "calypso", "empty"], help="use a simulated reader/card")
    p.add_argument("--sim-state", help="file that keeps the simulated card between invocations")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("readers", help="list readers")
    sp.add_argument("--all", action="store_true", help="list every PC/SC reader, not only OMNIKEY")
    sp.add_argument("--groups", action="store_true", help="list PC/SC reader groups instead")
    sp.set_defaults(func=cmd_readers)

    sub.add_parser("info", help="reader + card information").set_defaults(func=cmd_info)
    sub.add_parser("wait", help="wait for a card and show its ATR").set_defaults(func=cmd_wait)
    sp = sub.add_parser("atr", help="parse the card ATR (or a hex ATR given on the command line)")
    sp.add_argument("hex", nargs="*")
    sp.add_argument("--emv", action="store_true", help="also check EMV Book 1 (Level 1) ATR rules")
    sp.set_defaults(func=cmd_atr)

    sp = sub.add_parser("apdu", help="send raw APDU(s)")
    sp.add_argument("apdus", nargs="+", help='hex, e.g. "00 A4 04 00 08 A000000003021001"')
    sp.add_argument("--no-auto", action="store_true", help="do not issue GET RESPONSE automatically")
    sp.set_defaults(func=cmd_apdu)

    sp = sub.add_parser("script", help="run a file of hex APDUs (supports '# comment', 'expect 9000', 'sleep 0.5', 'reset')")
    sp.add_argument("file")
    sp.add_argument("--keep-going", action="store_true")
    sp.set_defaults(func=cmd_script)

    # iso
    iso = sub.add_parser("iso", help="ISO 7816-4 CPU card commands").add_subparsers(dest="iso_cmd", required=True)

    def iso_common(sp, select=True, pin=True):
        sp.add_argument("--cla", type=lambda x: int(x, 16), default=0x00, help="class byte (hex, default 00)")
        sp.add_argument("--extended", action="store_true", help="use extended-length APDUs (T=1, reader in extended mode)")
        if select:
            sp.add_argument("--aid", help="application to select first (hex)")
            sp.add_argument("--fid", help="file identifier to select (hex, e.g. 0001)")
            sp.add_argument("--path", help="path of FIDs from MF (hex)")
        if pin:
            sp.add_argument("--pin", help="PIN to VERIFY before the operation")
            sp.add_argument("--pin-ref", default="00", help="VERIFY P2 reference (hex, default 00)")

    sp = iso.add_parser("select", help="SELECT and show FCI")
    iso_common(sp, select=False, pin=False)
    sp.add_argument("--mf", action="store_true")
    sp.add_argument("--fid")
    sp.add_argument("--aid")
    sp.add_argument("--path")
    sp.set_defaults(func=cmd_iso_select)

    sp = iso.add_parser("read", help="READ BINARY")
    iso_common(sp)
    sp.add_argument("--offset", type=int, default=0)
    sp.add_argument("--length", type=int, default=None, help="bytes to read (default: whole file)")
    sp.add_argument("--sfi", type=int, default=None)
    sp.add_argument("--out", help="write to file instead of hexdump")
    sp.set_defaults(func=cmd_iso_read)

    sp = iso.add_parser("write", help="UPDATE BINARY")
    iso_common(sp)
    sp.add_argument("data", help="hex bytes, 'str:text' or '@file'")
    sp.add_argument("--offset", type=int, default=0)
    sp.add_argument("--sfi", type=int, default=None)
    sp.add_argument("--verify", action="store_true")
    sp.set_defaults(func=cmd_iso_write)

    sp = iso.add_parser("records", help="READ RECORD(s)")
    iso_common(sp)
    sp.add_argument("--number", type=int, default=0, help="record number (default: all)")
    sp.add_argument("--sfi", type=int, default=None)
    sp.set_defaults(func=cmd_iso_records)

    sp = iso.add_parser("verify", help="VERIFY PIN (without PIN: show remaining tries)")
    iso_common(sp, select=False, pin=False)
    sp.add_argument("pin", nargs="?")
    sp.add_argument("--aid")
    sp.add_argument("--pin-ref", default="00")
    sp.set_defaults(func=cmd_iso_verify)

    sp = iso.add_parser("change-pin", help="CHANGE REFERENCE DATA")
    iso_common(sp, select=False, pin=False)
    sp.add_argument("old")
    sp.add_argument("new")
    sp.add_argument("--aid")
    sp.add_argument("--pin-ref", default="00")
    sp.set_defaults(func=cmd_iso_change_pin)

    sp = iso.add_parser("challenge", help="GET CHALLENGE")
    iso_common(sp, select=False, pin=False)
    sp.add_argument("length", type=int, nargs="?", default=8)
    sp.set_defaults(func=cmd_iso_challenge)

    sp = iso.add_parser("getdata", help="GET DATA <tag>")
    iso_common(sp)
    sp.add_argument("tag", help="hex tag, e.g. 9F7F")
    sp.set_defaults(func=cmd_iso_getdata)

    # mem
    mem = sub.add_parser("mem", help="memory cards: SLE 4442/4432, SLE 4428/4418, I2C").add_subparsers(dest="mem_cmd", required=True)

    def mem_common(sp, psc=True):
        sp.add_argument("--kind", choices=["sle4442", "sle4428", "i2c"], help="force card type (default: from ATR)")
        sp.add_argument("--i2c-type", help="predefined I2C type name (see `mem i2c-types`)")
        sp.add_argument("--page-size", type=int)
        sp.add_argument("--address-bytes", type=int)
        sp.add_argument("--memory-size", type=int)
        if psc:
            sp.add_argument("--psc", help="PSC/PIN (hex) to verify first")

    sp = mem.add_parser("info", help="card type, size, PSC tries")
    mem_common(sp, psc=False)
    sp.set_defaults(func=cmd_mem_info)

    sp = mem.add_parser("read", help="read memory")
    mem_common(sp)
    sp.add_argument("--addr", type=int, default=0)
    sp.add_argument("--length", type=int, default=None)
    sp.add_argument("--out")
    sp.set_defaults(func=cmd_mem_read)

    sp = mem.add_parser("write", help="write memory (PSC required on SLE 4442/4428)")
    mem_common(sp)
    sp.add_argument("data", help="hex bytes, 'str:text' or '@file'")
    sp.add_argument("--addr", type=int, required=True)
    sp.add_argument("--verify", action="store_true")
    sp.set_defaults(func=cmd_mem_write)

    sp = mem.add_parser("verify", help="present the PSC")
    mem_common(sp, psc=False)
    sp.add_argument("psc_value", help="hex, 3 bytes (SLE 4442) or 2 bytes (SLE 4428)")
    sp.set_defaults(func=cmd_mem_verify)

    sp = mem.add_parser("change-psc", help="change the PSC")
    mem_common(sp, psc=False)
    sp.add_argument("old")
    sp.add_argument("new")
    sp.set_defaults(func=cmd_mem_change_psc)

    sp = mem.add_parser("protection", help="show protection bits")
    mem_common(sp, psc=False)
    sp.add_argument("--addr", type=int, default=0)
    sp.add_argument("--length", type=int, default=None)
    sp.set_defaults(func=cmd_mem_protection)

    sp = mem.add_parser("protect", help="IRREVERSIBLY set protection bits (compare and protect)")
    mem_common(sp)
    sp.add_argument("--addr", type=int, required=True)
    sp.add_argument("--length", type=int, default=1)
    sp.add_argument("--data", help="expected content (hex); default: current content")
    sp.add_argument("--yes", action="store_true")
    sp.set_defaults(func=cmd_mem_protect)

    mem.add_parser("i2c-types", help="list predefined I2C EEPROM types").set_defaults(func=cmd_i2c_types)

    # reader
    rd = sub.add_parser("reader", help="reader configuration (vendor API)").add_subparsers(dest="reader_cmd", required=True)
    rd.add_parser("caps", help="reader capabilities").set_defaults(func=cmd_reader_caps)
    sp = rd.add_parser("slot", help="get/set contact slot configuration")
    sp.add_argument("--exchange-level", choices=["tpdu", "apdu", "extended"])
    sp.add_argument("--voltage", help="'5V,3V,1.8V' sequence or 'auto'")
    sp.add_argument("--mode", choices=["iso", "emvco"])
    sp.set_defaults(func=cmd_reader_slot)
    sp = rd.add_parser("eeprom", help="read/write the 1 KiB user EEPROM")
    sp.add_argument("offset", type=int)
    sp.add_argument("length", type=int, nargs="?", default=16)
    sp.add_argument("--data", help="hex / str: / @file to write")
    sp.set_defaults(func=cmd_reader_eeprom)
    rd.add_parser("reboot", help="reboot the reader").set_defaults(func=cmd_reader_reboot)
    sp = rd.add_parser("factory-reset", help="restore factory defaults")
    sp.add_argument("--yes", action="store_true")
    sp.set_defaults(func=cmd_reader_factory_reset)
    sp = rd.add_parser("escape", help="send a raw CCID escape command (hex)")
    sp.add_argument("hex", nargs="+")
    sp.set_defaults(func=cmd_reader_escape)

    # emv
    emv = sub.add_parser("emv", help="EMV payment cards (read-only Level 2)").add_subparsers(dest="emv_cmd", required=True)

    def emv_common(sp):
        sp.add_argument("--aid", help="application to use (hex); default: first from PSE / probing")
        sp.add_argument("--no-probe", action="store_true", help="do not probe well-known AIDs when the PSE is missing")
        sp.add_argument("--country", default="0840", help="terminal country code for the PDOL (hex, default 0840 = US)")
        sp.add_argument("--currency", default="0840", help="transaction currency code for the PDOL (hex)")
        sp.add_argument("--amount", type=int, default=0, help="amount authorised in minor units for the PDOL")

    sp = emv.add_parser("apps", help="list applications (PSE or AID probing)")
    emv_common(sp)
    sp.set_defaults(func=cmd_emv_apps)
    sp = emv.add_parser("read", help="SELECT, GPO, read AFL records and decode tags")
    emv_common(sp)
    sp.add_argument("--unmask", action="store_true", help="print the full PAN / track 2")
    sp.set_defaults(func=cmd_emv_read)
    sp = emv.add_parser("log", help="read the transaction log if the card has one")
    emv_common(sp)
    sp.set_defaults(func=cmd_emv_log)

    # hbci
    hb = sub.add_parser("hbci", help="HBCI/FinTS DDV chip cards").add_subparsers(dest="hbci_cmd", required=True)

    def hbci_common(sp, pin=True):
        if pin:
            sp.add_argument("--pin", help="card PIN (typed on the PC; the 3021 is a class 1 reader)")

    sp = hb.add_parser("info", help="card type, card id, bank records, keys, signature counter")
    hbci_common(sp)
    sp.set_defaults(func=cmd_hbci_info)
    sp = hb.add_parser("pin", help="verify the PIN (without value: show remaining tries)")
    hbci_common(sp, pin=False)
    sp.add_argument("pin_value", nargs="?")
    sp.set_defaults(func=cmd_hbci_pin)
    sp = hb.add_parser("sigid", help="read (or --set) the signature counter EF_SEQ")
    hbci_common(sp)
    sp.add_argument("--set", type=int)
    sp.set_defaults(func=cmd_hbci_sigid)
    sp = hb.add_parser("sign", help="compute the DDV MAC over a 20-byte hash (hex)")
    hbci_common(sp)
    sp.add_argument("hash20")
    sp.set_defaults(func=cmd_hbci_sign)
    sp = hb.add_parser("keys", help="show key info; --derive N derives a session key with key N")
    hbci_common(sp)
    sp.add_argument("--derive", type=int)
    sp.set_defaults(func=cmd_hbci_keys)
    sp = hb.add_parser("bank", help="show / update EF_BNK bank records")
    hbci_common(sp)
    sp.add_argument("--record", type=int, default=1)
    sp.add_argument("--set-blz")
    sp.add_argument("--set-user")
    sp.add_argument("--set-host")
    sp.add_argument("--set-name")
    sp.set_defaults(func=cmd_hbci_bank)

    # calypso
    cal = sub.add_parser("calypso", help="Calypso transport cards (contact interface)").add_subparsers(dest="calypso_cmd", required=True)

    def cal_common(sp):
        sp.add_argument("--aid", help="application AID (hex); default 1TIC.ICA (315449432E494341)")
        sp.add_argument("--revision", type=int, choices=[2, 3], help="force Calypso revision (2 = CLA 94, 3 = CLA 00)")
        sp.add_argument("--implicit", action="store_true",
                        help="skip SELECT-by-AID and read files directly by SFI (older Rev2 / OPUS cards)")

    sp = cal.add_parser("info", help="select the application and show serial, startup info and files")
    cal_common(sp)
    sp.set_defaults(func=cmd_calypso_info)
    sp = cal.add_parser("dump", help="read every record of the standard transport files")
    cal_common(sp)
    sp.set_defaults(func=cmd_calypso_dump)
    sp = cal.add_parser("probe", help="diagnose how an unknown card wants to be addressed (resets between tries)")
    sp.set_defaults(func=cmd_calypso_probe)
    sp = cal.add_parser("read", help="read a file by SFI")
    cal_common(sp)
    sp.add_argument("--sfi", type=lambda x: int(x, 0), required=True, help="short file identifier, e.g. 0x07")
    sp.add_argument("--record", type=int, default=0, help="record number (default: all)")
    sp.set_defaults(func=cmd_calypso_read)
    sp = cal.add_parser("write", help="write a record inside a secure session (needs a SAM)")
    cal_common(sp)
    sp.add_argument("--sfi", type=lambda x: int(x, 0), required=True)
    sp.add_argument("--record", type=int, default=1)
    sp.add_argument("--append", action="store_true", help="APPEND instead of UPDATE")
    sp.add_argument("--data", required=True, help="hex, 'str:text' or '@file'")
    sp.add_argument("--sam-reader", help="reader holding the Calypso SAM (default: the other OMNIKEY reader)")
    sp.add_argument("--key-index", type=int, default=1, help="SAM key index (1 debit, 2 load, 3 perso)")
    sp.set_defaults(func=cmd_calypso_write)
    sp = cal.add_parser("counter", help="increase/decrease a counter inside a secure session (needs a SAM)")
    cal_common(sp)
    sp.add_argument("--sfi", type=lambda x: int(x, 0), default=0x19)
    sp.add_argument("--counter", type=int, default=0, help="counter index within the file")
    sp.add_argument("--increase", type=int)
    sp.add_argument("--decrease", type=int)
    sp.add_argument("--sam-reader")
    sp.add_argument("--key-index", type=int, default=1)
    sp.set_defaults(func=cmd_calypso_counter)

    # ccid / monitor / ctapi
    sp = sub.add_parser("ccid", help="USB CCID descriptor (Linux sysfs) and PC/SC part 10 properties")
    sp.add_argument("--all-usb", action="store_true", help="list every CCID device, not only HID/OMNIKEY")
    sp.set_defaults(func=cmd_ccid)
    sp = sub.add_parser("monitor", help="print card insert/remove and reader hot-plug events")
    sp.add_argument("--no-hotplug", action="store_true")
    sp.set_defaults(func=cmd_monitor)
    sp = sub.add_parser("ctapi", help="send CT-BCS / ICC commands through the CT-API interface")
    sp.add_argument("commands", nargs="+", help='hex, e.g. "20 12 01 01 01 0F 00" (REQUEST ICC with ATR)')
    sp.add_argument("--dad", choices=["ct", "icc"], default="ct")
    sp.add_argument("--ctn", type=int, default=1)
    sp.add_argument("--port", type=int, default=0)
    sp.add_argument("--library", help="path to a vendor CT-API shared library instead of the PC/SC bridge")
    sp.set_defaults(func=cmd_ctapi)

    # access
    ac = sub.add_parser("access", help="access-control system").add_subparsers(dest="access_cmd", required=True)

    def access_common(sp):
        sp.add_argument("--db", default="access.sqlite3")
        sp.add_argument("--key-file", default="site.key")
        sp.add_argument("--site-code", type=int, default=None)
        sp.add_argument("--kind", choices=["sle4442", "sle4428", "i2c"], help="force memory card type")
        sp.add_argument("--mem-offset", type=int, default=32, help="credential block address on memory cards")
        sp.add_argument("--iso-fid", default="0001", help="transparent EF holding the credential on CPU cards (hex)")
        sp.add_argument("--iso-aid", help="application to select on CPU cards (hex)")
        sp.add_argument("--iso-pin", help="PIN needed to write the EF on CPU cards")
        sp.add_argument("--iso-challenge", action="store_true", help="require INTERNAL AUTHENTICATE on CPU cards")

    sp = ac.add_parser("init", help="create database and site key")
    access_common(sp)
    sp.set_defaults(func=cmd_access_init, site_code_required=True)
    sp = ac.add_parser("holder", help="manage card holders")
    access_common(sp)
    sp.add_argument("action", choices=["add", "list", "enable", "disable"])
    sp.add_argument("name", nargs="?", help="holder name (add) or id (enable/disable)")
    sp.add_argument("--level", type=int, default=1)
    sp.add_argument("--note")
    sp.set_defaults(func=cmd_access_holder)
    sp = ac.add_parser("enroll", help="write a credential to the inserted card")
    access_common(sp)
    sp.add_argument("--holder", required=True, help="holder name or id")
    sp.add_argument("--card-id", type=int)
    sp.add_argument("--level", type=int)
    sp.add_argument("--expires-days", type=int, default=0)
    sp.add_argument("--psc", help="memory card PSC (hex)")
    sp.add_argument("--protect-binding", action="store_true", help="irreversibly protect bytes 0..31 (SLE cards)")
    sp.add_argument("--note")
    sp.set_defaults(func=cmd_access_enroll)
    sp = ac.add_parser("check", help="check the inserted card once")
    access_common(sp)
    sp.set_defaults(func=cmd_access_check)
    sp = ac.add_parser("monitor", help="run the door controller loop")
    access_common(sp)
    sp.add_argument("--exec", help="shell command on grant, e.g. 'gpio set 17 1'; placeholders {card_id} {holder} {granted} {level}")
    sp.add_argument("--exec-on-deny", action="store_true")
    sp.add_argument("--webhook", help="POST a JSON decision to this URL")
    sp.add_argument("--once", action="store_true")
    sp.set_defaults(func=cmd_access_monitor)
    sp = ac.add_parser("revoke", help="revoke (or --restore) a card id")
    access_common(sp)
    sp.add_argument("card_id", type=int)
    sp.add_argument("--restore", action="store_true")
    sp.set_defaults(func=cmd_access_revoke)
    sp = ac.add_parser("cards", help="list enrolled cards")
    access_common(sp)
    sp.set_defaults(func=cmd_access_cards)
    sp = ac.add_parser("log", help="show access events")
    access_common(sp)
    sp.add_argument("-n", "--limit", type=int, default=50)
    sp.set_defaults(func=cmd_access_log)
    sp = ac.add_parser("erase", help="wipe the credential block on the inserted card")
    access_common(sp)
    sp.add_argument("--psc")
    sp.set_defaults(func=cmd_access_erase)
    sp = ac.add_parser("schedule", help="time windows per access level")
    access_common(sp)
    sp.add_argument("action", choices=["add", "list", "clear"])
    sp.add_argument("--level", type=int, default=None)
    sp.add_argument("--days", default="mon-fri", help="'mon-fri', 'mon,wed,fri' or 'all'")
    sp.add_argument("--start", default="00:00")
    sp.add_argument("--end", default="24:00")
    sp.set_defaults(func=cmd_access_schedule)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "site_code_required", False) and args.site_code is None:
        parser.error("access init requires --site-code")
    if getattr(args, "access_cmd", None) == "schedule" and args.action == "add" and args.level is None:
        parser.error("schedule add requires --level")
    try:
        return args.func(args)
    except NoCardError as exc:
        print(f"No card: {exc}", file=sys.stderr)
        return 4
    except CardError as exc:
        print(f"Card error: {exc}", file=sys.stderr)
        return 2
    except VendorError as exc:
        print(f"Reader error: {exc}", file=sys.stderr)
        return 2
    except OmnikeyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
