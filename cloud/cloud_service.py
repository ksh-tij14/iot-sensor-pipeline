"""Cloud node: the same processing as the edge, plus a backup store of every
raw chunk (SQLite) kept together with the device's signature, used to recover
the original reading when edge and cloud results disagree. Backups that fail
re-verification are quarantined.

Run from the repo root:  python -m cloud.cloud_service
"""

import json
import logging
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from shared.api_models import ProcessIn
from shared.config import CLOUD_PORT, SERVICE_HOST
from shared.processing import assess_comfort
from shared.service_utils import install_malformed_handler, log_event, reject, run_service

HOP = "fork-cloud"
DB_PATH = Path(os.environ.get("CLOUD_DB_PATH", Path(__file__).parent / "data" / "raw_chunks.db"))

log = logging.getLogger("cloud")
app = FastAPI(title="IoT cloud node")
install_malformed_handler(app, log, HOP)


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE IF NOT EXISTS raw_chunks (
            chunk_id         TEXT PRIMARY KEY,
            received_at      REAL NOT NULL,
            sensor_id        TEXT,
            timestamp        INTEGER,
            counter          INTEGER,
            data             TEXT NOT NULL,     -- the original data, as JSON
            sensor_signature TEXT               -- the device's ECDSA signature over it
        )""")
    db.execute("""
        CREATE TABLE IF NOT EXISTS final_results (
            chunk_id    TEXT PRIMARY KEY,
            stored_at   REAL NOT NULL,
            result      TEXT NOT NULL,          -- validated result, as JSON
            recovered   INTEGER NOT NULL DEFAULT 0   -- 1 = recomputed from a verified backup
        )""")
    db.execute("""
        CREATE TABLE IF NOT EXISTS quarantine (
            chunk_id       TEXT PRIMARY KEY,
            quarantined_at REAL NOT NULL,
            reason         TEXT NOT NULL
        )""")
    # Stores created before signatures/recovery flags were added.
    for table, column, decl in [("raw_chunks", "sensor_signature", "TEXT"),
                                ("final_results", "recovered", "INTEGER NOT NULL DEFAULT 0")]:
        if column not in {r["name"] for r in db.execute(f"PRAGMA table_info({table})")}:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
    return db


@app.post("/process")
async def process(incoming: ProcessIn, request: Request):
    chunk_id = str(incoming.chunk_id)
    data = incoming.data.model_dump()

    # Store the raw chunk BEFORE processing, so the backup exists even if
    # processing fails. chunk_id is the primary key, so a resent chunk is refused.
    with closing(connect()) as db, db:
        try:
            db.execute("INSERT INTO raw_chunks (chunk_id, received_at, sensor_id, timestamp, counter, data, "
                       "sensor_signature) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (chunk_id, time.time(), incoming.sensor_id, incoming.timestamp,
                        incoming.counter, json.dumps(data), incoming.sensor_signature))
        except sqlite3.IntegrityError:
            return reject(log, HOP, request, 409, "duplicate_chunk_id", chunk_id=chunk_id)

    result = assess_comfort(data)
    log_event(log, logging.INFO, "processed", HOP, chunk_id=chunk_id, result=result)
    return {"chunk_id": chunk_id, "result": result}


@app.get("/retrieve/{chunk_id}")
async def retrieve(chunk_id: str):
    """The raw backup, with its signature. Callers must verify it before use."""
    with closing(connect()) as db:
        row = db.execute("SELECT * FROM raw_chunks WHERE chunk_id = ?", (chunk_id,)).fetchone()
    if row is None:
        return JSONResponse(status_code=404, content={"status": "not_found", "chunk_id": chunk_id})
    return {**dict(row), "data": json.loads(row["data"])}


@app.get("/results/recent")
async def recent_results(limit: int = 60, sensor_id: Optional[str] = None):
    """Newest raw chunks with their validated result, if any (for the dashboard)."""
    limit = max(1, min(limit, 500))
    query = ("SELECT r.chunk_id, r.received_at, r.sensor_id, r.timestamp, r.counter, r.data, "
             "f.result, f.recovered, q.reason AS quarantined "
             "FROM raw_chunks r LEFT JOIN final_results f ON f.chunk_id = r.chunk_id "
             "LEFT JOIN quarantine q ON q.chunk_id = r.chunk_id")
    params: list = []
    if sensor_id:
        query += " WHERE r.sensor_id = ?"
        params.append(sensor_id)
    query += " ORDER BY r.received_at DESC LIMIT ?"
    params.append(limit)
    with closing(connect()) as db:
        rows = db.execute(query, params).fetchall()
    return [{**dict(r), "data": json.loads(r["data"]), "recovered": bool(r["recovered"]),
             "result": json.loads(r["result"]) if r["result"] else None} for r in rows]


class FinalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    chunk_id: UUID
    result: dict[str, Any]
    recovered: bool = False


@app.post("/forward")
async def forward(body: FinalIn, request: Request):
    """Final storage: validation sends results here once edge and cloud agreed,
    or after recomputing from a verified backup. Only for chunks this node
    actually received, and never for quarantined ones."""
    chunk_id = str(body.chunk_id)
    with closing(connect()) as db, db:
        if not db.execute("SELECT 1 FROM raw_chunks WHERE chunk_id = ?", (chunk_id,)).fetchone():
            return reject(log, HOP, request, 404, "unknown_chunk_id", chunk_id=chunk_id)
        if db.execute("SELECT 1 FROM quarantine WHERE chunk_id = ?", (chunk_id,)).fetchone():
            return reject(log, HOP, request, 409, "chunk_quarantined", chunk_id=chunk_id)
        db.execute("INSERT OR REPLACE INTO final_results (chunk_id, stored_at, result, recovered) "
                   "VALUES (?, ?, ?, ?)", (chunk_id, time.time(), json.dumps(body.result), int(body.recovered)))
    log_event(log, logging.INFO, "final_stored", HOP, chunk_id=chunk_id, recovered=body.recovered)
    return {"status": "stored", "chunk_id": chunk_id, "recovered": body.recovered}


class QuarantineIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    chunk_id: UUID
    reason: str


@app.post("/quarantine")
async def quarantine(body: QuarantineIn):
    """Set a chunk aside: its backup failed verification, so it must never be
    used, and any result stored for it is withdrawn."""
    chunk_id = str(body.chunk_id)
    with closing(connect()) as db, db:
        db.execute("INSERT OR REPLACE INTO quarantine VALUES (?, ?, ?)", (chunk_id, time.time(), body.reason[:500]))
        db.execute("DELETE FROM final_results WHERE chunk_id = ?", (chunk_id,))
    log_event(log, logging.WARNING, "quarantined", HOP, chunk_id=chunk_id, reason=body.reason[:200])
    return {"status": "quarantined", "chunk_id": chunk_id}


@app.get("/quarantine")
async def list_quarantine(limit: int = 100):
    with closing(connect()) as db:
        rows = db.execute("SELECT * FROM quarantine ORDER BY quarantined_at DESC LIMIT ?",
                          (max(1, min(limit, 500)),)).fetchall()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    run_service(app, SERVICE_HOST, CLOUD_PORT,
                banner=f"Cloud listening on {SERVICE_HOST}:{CLOUD_PORT}, raw store: {DB_PATH}")
