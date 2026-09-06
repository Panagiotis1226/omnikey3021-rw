"""SQLite backed registry of card holders, cards, schedules and access events."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS holders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    level INTEGER NOT NULL DEFAULT 1,
    active INTEGER NOT NULL DEFAULT 1,
    created REAL NOT NULL,
    note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS cards (
    uid TEXT PRIMARY KEY,
    holder_id INTEGER REFERENCES holders(id),
    site_code INTEGER NOT NULL,
    card_id INTEGER NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    issued REAL NOT NULL,
    expires REAL NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS schedules (
    level INTEGER NOT NULL,
    dow INTEGER NOT NULL,         -- 0 = Monday ... 6 = Sunday
    start_min INTEGER NOT NULL,   -- minutes after midnight
    end_min INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    uid TEXT,
    card_id INTEGER,
    holder TEXT,
    granted INTEGER NOT NULL,
    reason TEXT NOT NULL,
    detail TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
"""


@dataclass
class Holder:
    id: int
    name: str
    level: int
    active: bool
    created: float
    note: str = ""


@dataclass
class CardRecord:
    uid: str
    holder_id: int | None
    site_code: int
    card_id: int
    kind: str
    issued: float
    expires: float
    revoked: bool
    note: str = ""


class AccessStore:
    def __init__(self, path: str | Path = "access.sqlite3"):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # -- meta ----------------------------------------------------------------------
    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, value))
        self.conn.commit()

    def next_card_id(self) -> int:
        row = self.conn.execute("SELECT COALESCE(MAX(card_id), 0) + 1 AS n FROM cards").fetchone()
        return int(row["n"])

    # -- holders ---------------------------------------------------------------------
    def add_holder(self, name: str, level: int = 1, note: str = "") -> Holder:
        cur = self.conn.execute("INSERT INTO holders(name, level, active, created, note) VALUES (?, ?, 1, ?, ?)",
                                (name, level, time.time(), note))
        self.conn.commit()
        return self.get_holder(cur.lastrowid)  # type: ignore[arg-type]

    def get_holder(self, holder_id: int) -> Holder | None:
        row = self.conn.execute("SELECT * FROM holders WHERE id=?", (holder_id,)).fetchone()
        return Holder(row["id"], row["name"], row["level"], bool(row["active"]), row["created"], row["note"]) if row else None

    def find_holder(self, name: str) -> Holder | None:
        row = self.conn.execute("SELECT * FROM holders WHERE name=? COLLATE NOCASE", (name,)).fetchone()
        return Holder(row["id"], row["name"], row["level"], bool(row["active"]), row["created"], row["note"]) if row else None

    def set_holder_active(self, holder_id: int, active: bool) -> None:
        self.conn.execute("UPDATE holders SET active=? WHERE id=?", (1 if active else 0, holder_id))
        self.conn.commit()

    def holders(self) -> list[Holder]:
        rows = self.conn.execute("SELECT * FROM holders ORDER BY id").fetchall()
        return [Holder(r["id"], r["name"], r["level"], bool(r["active"]), r["created"], r["note"]) for r in rows]

    # -- cards -----------------------------------------------------------------------------
    def add_card(self, uid: str, holder_id: int | None, site_code: int, card_id: int, kind: str,
                 issued: float, expires: float = 0, note: str = "") -> CardRecord:
        self.conn.execute(
            "INSERT OR REPLACE INTO cards(uid, holder_id, site_code, card_id, kind, issued, expires, revoked, note) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
            (uid, holder_id, site_code, card_id, kind, issued, expires, note))
        self.conn.commit()
        return self.get_card(uid)  # type: ignore[return-value]

    def get_card(self, uid: str) -> CardRecord | None:
        row = self.conn.execute("SELECT * FROM cards WHERE uid=?", (uid,)).fetchone()
        return self._card(row) if row else None

    def get_card_by_id(self, card_id: int) -> CardRecord | None:
        row = self.conn.execute("SELECT * FROM cards WHERE card_id=?", (card_id,)).fetchone()
        return self._card(row) if row else None

    def revoke_card(self, card_id: int, revoked: bool = True) -> bool:
        cur = self.conn.execute("UPDATE cards SET revoked=? WHERE card_id=?", (1 if revoked else 0, card_id))
        self.conn.commit()
        return cur.rowcount > 0

    def cards(self, include_revoked: bool = True) -> list[CardRecord]:
        sql = "SELECT * FROM cards" + ("" if include_revoked else " WHERE revoked=0") + " ORDER BY card_id"
        return [self._card(r) for r in self.conn.execute(sql).fetchall()]

    @staticmethod
    def _card(row: sqlite3.Row) -> CardRecord:
        return CardRecord(row["uid"], row["holder_id"], row["site_code"], row["card_id"], row["kind"], row["issued"],
                          row["expires"], bool(row["revoked"]), row["note"])

    # -- schedules -------------------------------------------------------------------------------
    def add_schedule(self, level: int, days: Iterable[int], start_min: int, end_min: int) -> None:
        for d in days:
            self.conn.execute("INSERT INTO schedules(level, dow, start_min, end_min) VALUES (?, ?, ?, ?)",
                              (level, d, start_min, end_min))
        self.conn.commit()

    def clear_schedules(self, level: int | None = None) -> None:
        if level is None:
            self.conn.execute("DELETE FROM schedules")
        else:
            self.conn.execute("DELETE FROM schedules WHERE level=?", (level,))
        self.conn.commit()

    def schedules(self, level: int | None = None) -> list[tuple[int, int, int, int]]:
        if level is None:
            rows = self.conn.execute("SELECT level, dow, start_min, end_min FROM schedules ORDER BY level, dow").fetchall()
        else:
            rows = self.conn.execute("SELECT level, dow, start_min, end_min FROM schedules WHERE level=? ORDER BY dow",
                                     (level,)).fetchall()
        return [tuple(r) for r in rows]

    def schedule_allows(self, level: int, when: float | None = None) -> bool:
        """True when no schedule is defined for ``level`` or the current time falls in one."""
        rows = self.schedules(level)
        if not rows:
            return True
        t = time.localtime(when if when is not None else time.time())
        minute = t.tm_hour * 60 + t.tm_min
        return any(dow == t.tm_wday and start <= minute < end for _, dow, start, end in rows)

    # -- events --------------------------------------------------------------------------------------
    def log_event(self, uid: str | None, card_id: int | None, holder: str | None, granted: bool, reason: str,
                  detail: str = "") -> None:
        self.conn.execute("INSERT INTO events(ts, uid, card_id, holder, granted, reason, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
                          (time.time(), uid, card_id, holder, 1 if granted else 0, reason, detail))
        self.conn.commit()

    def events(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
