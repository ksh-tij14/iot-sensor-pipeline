"""Shared, tamper-evident event store, read by the dashboard.

When EVENT_DB_PATH is set, every service's log_event() also appends the event
to one SQLite file. Each entry stores entry_hash = HMAC(EVENT_LOG_KEY, fields +
previous entry_hash), so editing, deleting or reordering any entry breaks the
chain, and (unlike a plain SHA-256 chain) someone with database access can't
recompute it without the key. verify_chain() checks the whole chain.

Recording is best-effort: if it fails, the event is still in the service's log
and the pipeline carries on.
"""

import hashlib
import hmac
import json
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Optional

EVENT_DB_PATH = os.environ.get("EVENT_DB_PATH")
EVENT_LOG_KEY = os.environ.get("EVENT_LOG_KEY", "dev-event-log-key-change-me").encode("utf-8")
# Older events are pruned so the file doesn't grow forever. ~250k entries is
# about 8 hours with the board and the virtual board at 2 s each (~95 MB).
KEEP_EVENTS = 250_000
GENESIS = "0" * 64
FIELDS = ("time", "service", "event", "hop", "sensor_id", "counter", "chunk_id", "reason", "details")


def _connect(path: str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=5, isolation_level=None)   # explicit transactions below
    db.row_factory = sqlite3.Row
    # WAL: readers (the dashboard, every second) never block writers, and a
    # write is one append instead of journal + database syncs. In the default
    # mode one slow sync stalled every service for 5 s (a 1-hour run).
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")   # safe in WAL: a crash may lose the last entries, never corrupts
    db.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            time       REAL NOT NULL,
            service    TEXT,
            event      TEXT NOT NULL,
            hop        TEXT,
            sensor_id  TEXT,
            counter    INTEGER,
            chunk_id   TEXT,
            reason     TEXT,
            details    TEXT,        -- all event fields, as JSON
            prev_hash  TEXT,
            entry_hash TEXT
        )""")
    columns = {r["name"] for r in db.execute("PRAGMA table_info(events)")}
    for col in ("prev_hash", "entry_hash"):                      # stores created before chaining
        if col not in columns:
            db.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
    return db


def _entry_hash(values: dict, prev_hash: str, key: bytes) -> str:
    material = json.dumps([values[f] for f in FIELDS] + [prev_hash], separators=(",", ":"), default=str)
    return hmac.new(key, material.encode("utf-8"), hashlib.sha256).hexdigest()


def record_event(service: str, event: str, hop: str, fields: dict, path: Optional[str] = None,
                 key: bytes = None) -> None:
    path = path or EVENT_DB_PATH
    if not path:
        return
    values = {"time": time.time(), "service": service, "event": event, "hop": hop,
              "sensor_id": fields.get("sensor_id"), "counter": fields.get("counter"),
              "chunk_id": fields.get("chunk_id"), "reason": fields.get("reason"),
              "details": json.dumps(fields, default=str, sort_keys=True)}
    try:
        with closing(_connect(path)) as db:
            # BEGIN IMMEDIATE serialises writers across all services, so two
            # services can't both chain onto the same previous entry.
            db.execute("BEGIN IMMEDIATE")
            try:
                last = db.execute("SELECT entry_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
                prev = (last["entry_hash"] if last else None) or GENESIS
                cur = db.execute(
                    f"INSERT INTO events ({', '.join(FIELDS)}, prev_hash, entry_hash) "
                    f"VALUES ({', '.join('?' * len(FIELDS))}, ?, ?)",
                    [values[f] for f in FIELDS] + [prev, _entry_hash(values, prev, key or EVENT_LOG_KEY)])
                if cur.lastrowid % 500 == 0:
                    db.execute("DELETE FROM events WHERE id <= ?", (cur.lastrowid - KEEP_EVENTS,))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
    except sqlite3.Error:
        pass  # the dashboard is optional; never fail a request over it


def verify_chain(path: str, key: bytes = None) -> dict:
    """Recompute every entry's hash and check each links to the one before.
    Pruned history is fine: the oldest remaining entry anchors the chain."""
    if not path or not Path(path).exists():
        return {"ok": True, "checked": 0, "first_bad_id": None, "reason": "no events yet"}
    with closing(_connect(path)) as db:
        rows = db.execute("SELECT * FROM events WHERE entry_hash IS NOT NULL ORDER BY id").fetchall()
    prev = None
    for r in rows:
        values = {f: r[f] for f in FIELDS}
        if prev is not None and r["prev_hash"] != prev:
            return {"ok": False, "checked": len(rows), "first_bad_id": r["id"],
                    "reason": "entry doesn't link to the previous one (deleted or reordered)"}
        if not hmac.compare_digest(_entry_hash(values, r["prev_hash"], key or EVENT_LOG_KEY), r["entry_hash"]):
            return {"ok": False, "checked": len(rows), "first_bad_id": r["id"],
                    "reason": "entry contents don't match its hash (edited)"}
        prev = r["entry_hash"]
    return {"ok": True, "checked": len(rows), "first_bad_id": None, "reason": "chain intact"}


def read_events(path: str, limit: int = 100, events: Optional[list[str]] = None,
                after_id: int = 0, sensor_id: Optional[str] = None) -> list[dict]:
    """Newest first."""
    if not path or not Path(path).exists():
        return []
    query = "SELECT * FROM events WHERE id > ?"
    params: list = [after_id]
    if events:
        query += f" AND event IN ({','.join('?' * len(events))})"
        params += events
    if sensor_id:
        query += " AND sensor_id = ?"
        params.append(sensor_id)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with closing(_connect(path)) as db:
        rows = db.execute(query, params).fetchall()
    return [{**dict(r), "details": json.loads(r["details"] or "{}")} for r in rows]


def count_events(path: str, sensor_id: Optional[str] = None) -> dict:
    """{event: count} and {(event, hop): count} over everything stored, or
    only events for one sensor."""
    if not path or not Path(path).exists():
        return {"by_event": {}, "by_event_hop": {}}
    where, params = ("WHERE sensor_id = ?", [sensor_id]) if sensor_id else ("", [])
    with closing(_connect(path)) as db:
        by_event = dict(db.execute(f"SELECT event, COUNT(*) FROM events {where} GROUP BY event", params).fetchall())
        by_hop = {f"{e}|{h}": n for e, h, n in
                  db.execute(f"SELECT event, hop, COUNT(*) FROM events {where} GROUP BY event, hop", params).fetchall()}
    return {"by_event": by_event, "by_event_hop": by_hop}
