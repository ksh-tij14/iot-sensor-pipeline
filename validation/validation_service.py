"""Validation: compares edge and cloud results for each chunk, recovers from a
verified backup when they disagree, and flags anomalous readings.

- Match: the result goes to final storage (POST CLOUD_URL/forward).
- Mismatch: both results are discarded. The raw backup is fetched from the cloud
  and its ECDSA device signature re-verified - a backup is never trusted on its
  own authority. Verified: the result is recomputed from it and stored, marked
  as recovered. Not verified (or missing): the chunk is quarantined.
- Anomaly: a separate flag. It doesn't block forwarding; a real reading can be unusual.

Run from the repo root:  python -m validation.validation_service
"""

import logging
import os
import sqlite3
import statistics
import time
from collections import deque
from contextlib import closing
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from shared.config import (ANOMALY_MIN_HISTORY, ANOMALY_MIN_STDDEV, ANOMALY_STDDEV_THRESHOLD,
                           ANOMALY_WINDOW, CLOUD_URL, SERVICE_HOST, VALIDATION_PORT,
                           VALIDATION_TOLERANCE, load_keystore)
from shared.processing import assess_comfort
from shared.schemas import SignedChunk
from shared.service_utils import install_malformed_handler, log_event, run_service
from shared.verification import check_sensor_signature

HOP = "edge-cloud-validation"
CLOUD_TIMEOUT_SECONDS = 1.0
ANOMALY_METRICS = ("temp_c", "humidity_pct")  # the sensor's actual readings
STATE_DB = os.environ.get("VALIDATION_STATE_DB")  # persists anomaly history if set

log = logging.getLogger("validation")
app = FastAPI(title="IoT validation")
install_malformed_handler(app, log, HOP)

# (sensor_id, metric) -> last ANOMALY_WINDOW values; also saved to STATE_DB.
history: dict[tuple[str, str], deque] = {}


def _state_db() -> sqlite3.Connection:
    Path(STATE_DB).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(STATE_DB, timeout=5)
    db.execute("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, "
               "sensor_id TEXT, metric TEXT, value REAL)")
    return db


def _history_for(sensor_id: str, metric: str) -> deque:
    key = (sensor_id, metric)
    if key not in history:
        past = deque(maxlen=ANOMALY_WINDOW)
        if STATE_DB:
            with closing(_state_db()) as db:
                rows = db.execute("SELECT value FROM history WHERE sensor_id = ? AND metric = ? "
                                  "ORDER BY id DESC LIMIT ?", (sensor_id, metric, ANOMALY_WINDOW)).fetchall()
            past.extend(v for (v,) in reversed(rows))
        history[key] = past
    return history[key]


def _remember(sensor_id: str, metric: str, value: float) -> None:
    _history_for(sensor_id, metric).append(value)
    if STATE_DB:
        with closing(_state_db()) as db, db:
            cur = db.execute("INSERT INTO history (sensor_id, metric, value) VALUES (?, ?, ?)",
                             (sensor_id, metric, value))
            if cur.lastrowid % 1000 == 0:   # keep the table small
                db.execute("DELETE FROM history WHERE id <= ?", (cur.lastrowid - 5000,))


class ValidateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chunk_id: UUID
    cloud_result: dict[str, Any]
    edge_result: dict[str, Any]
    sensor_id: Optional[str] = None  # keeps one sensor's history separate from another's


def is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def compare_results(cloud: dict, edge: dict, tolerance: float = VALIDATION_TOLERANCE) -> dict:
    """Field-by-field comparison. Numbers must agree within `tolerance` relative
    difference; anything else (e.g. the comfort label) must be equal. Returns
    {field: details} for every field that doesn't match; empty means a match."""
    differences = {}
    for field in sorted(cloud.keys() | edge.keys()):
        if field not in cloud or field not in edge:
            differences[field] = {"cloud": cloud.get(field), "edge": edge.get(field),
                                  "problem": "missing on one side"}
            continue
        c, e = cloud[field], edge[field]
        if is_number(c) and is_number(e):
            if c == e:
                continue
            rel_diff = abs(c - e) / max(abs(c), abs(e))
            if rel_diff > tolerance:
                differences[field] = {"cloud": c, "edge": e, "relative_difference": round(rel_diff, 4),
                                      "tolerance": tolerance}
        elif c != e:
            differences[field] = {"cloud": c, "edge": e, "problem": "values differ"}
    return differences


def check_anomalies(sensor_id: str, result: dict) -> list[dict]:
    """Compare each reading with its recent history, then add it to that history.
    Returns details for every metric that was checked."""
    checks = []
    for metric in ANOMALY_METRICS:
        value = result.get(metric)
        if not is_number(value):
            continue
        past = _history_for(sensor_id, metric)
        if len(past) >= ANOMALY_MIN_HISTORY:
            mean = statistics.fmean(past)
            stddev = statistics.pstdev(past)
            used_stddev = max(stddev, ANOMALY_MIN_STDDEV)
            deviations = abs(value - mean) / used_stddev
            checks.append({"metric": metric, "value": value, "mean": round(mean, 2),
                           "stddev": round(stddev, 2), "stddev_used": round(used_stddev, 2),
                           "deviations": round(deviations, 2),
                           "anomaly": deviations > ANOMALY_STDDEV_THRESHOLD})
        else:
            checks.append({"metric": metric, "value": value, "anomaly": False,
                           "note": f"building history ({len(past)}/{ANOMALY_MIN_HISTORY})"})
        # Every trusted reading joins the history, anomalies included, so a lasting
        # real change (heating switched on) soon becomes the new normal.
        _remember(sensor_id, metric, value)
    return checks


def verify_backup(backup: dict) -> Optional[str]:
    """None if the backup carries a valid signature from its device; else why not."""
    if not backup.get("sensor_signature"):
        return "backup has no device signature"
    try:
        chunk = SignedChunk(sensor_id=backup["sensor_id"], timestamp=backup["timestamp"],
                            counter=backup["counter"], data=backup["data"],
                            sensor_signature=backup["sensor_signature"])
    except (KeyError, TypeError):
        return "backup is incomplete"
    problem = check_sensor_signature(chunk, load_keystore())
    return f"backup failed verification: {problem}" if problem else None


async def forward_final(chunk_id: str, result: dict, recovered: bool = False) -> dict:
    async with httpx.AsyncClient(timeout=CLOUD_TIMEOUT_SECONDS) as client:
        response = await client.post(f"{CLOUD_URL}/forward",
                                     json={"chunk_id": chunk_id, "result": result, "recovered": recovered})
        response.raise_for_status()
        return response.json()


async def retrieve_backup(chunk_id: str) -> dict:
    async with httpx.AsyncClient(timeout=CLOUD_TIMEOUT_SECONDS) as client:
        response = await client.get(f"{CLOUD_URL}/retrieve/{chunk_id}")
        response.raise_for_status()
        return response.json()


async def quarantine(chunk_id: str, reason: str) -> None:
    async with httpx.AsyncClient(timeout=CLOUD_TIMEOUT_SECONDS) as client:
        response = await client.post(f"{CLOUD_URL}/quarantine", json={"chunk_id": chunk_id, "reason": reason})
        response.raise_for_status()


async def recover(chunk_id: str, sensor_id: Optional[str]) -> dict:
    """Fetch the backup, verify it, and either restore a recomputed result or quarantine."""
    try:
        backup = await retrieve_backup(chunk_id)
    except httpx.HTTPError as e:
        backup, problem = None, f"backup unavailable: {e!r}"
    else:
        problem = verify_backup(backup)

    if problem is None:
        result = assess_comfort(backup["data"])       # recomputed from the verified original
        try:
            await forward_final(chunk_id, result, recovered=True)
        except httpx.HTTPError as e:
            log_event(log, logging.ERROR, "final_forward_failed", HOP, chunk_id=chunk_id, error=repr(e))
        log_event(log, logging.WARNING, "recovered", HOP, chunk_id=chunk_id, sensor_id=sensor_id,
                  counter=backup.get("counter"))
        return {"action": "discarded results; restored result recomputed from the verified backup",
                "recovered": True, "result": result, "backup": backup}

    try:
        await quarantine(chunk_id, problem)
    except httpx.HTTPError as e:
        log_event(log, logging.ERROR, "quarantine_failed", HOP, chunk_id=chunk_id, error=repr(e))
    log_event(log, logging.ERROR, "quarantined", HOP, chunk_id=chunk_id, sensor_id=sensor_id, reason=problem)
    return {"action": "discarded results; backup could not be verified, chunk quarantined",
            "recovered": False, "reason": problem, "backup": backup}


@app.post("/validate")
async def validate(incoming: ValidateIn):
    chunk_id = str(incoming.chunk_id)
    differences = compare_results(incoming.cloud_result, incoming.edge_result)
    cloud_edge = {"passed": not differences, "tolerance": VALIDATION_TOLERANCE,
                  "differences": differences}

    if differences:
        # Neither result is kept. The cloud's raw backup, stored (with the
        # device's signature) before any processing, is the authoritative copy.
        log_event(log, logging.WARNING, "validation_failed", HOP, chunk_id=chunk_id,
                  sensor_id=incoming.sensor_id, check="cloud_edge_mismatch",
                  differences=differences)
        recovery = await recover(chunk_id, incoming.sensor_id)
        return {"chunk_id": chunk_id, "status": "mismatch", "timestamp": time.time(),
                "checks": {"cloud_edge": cloud_edge, "anomaly": "skipped: results not trusted"},
                **recovery}

    anomaly_checks = check_anomalies(incoming.sensor_id or "unknown", incoming.cloud_result)
    flagged = [c for c in anomaly_checks if c["anomaly"]]
    for c in flagged:
        log_event(log, logging.WARNING, "anomaly", HOP, chunk_id=chunk_id,
                  sensor_id=incoming.sensor_id, check="anomaly", **c)

    try:
        forwarded = await forward_final(chunk_id, incoming.cloud_result)
        action = "forwarded to cloud"
    except httpx.HTTPError as e:
        forwarded = {"error": repr(e)}
        action = "forward to cloud failed"
        log_event(log, logging.ERROR, "final_forward_failed", HOP, chunk_id=chunk_id, error=repr(e))

    log_event(log, logging.INFO, "validated", HOP, chunk_id=chunk_id, sensor_id=incoming.sensor_id,
              anomalies=[c["metric"] for c in flagged])
    return {"chunk_id": chunk_id, "status": "match", "timestamp": time.time(),
            "checks": {"cloud_edge": cloud_edge,
                       "anomaly": {"flagged": bool(flagged), "details": anomaly_checks}},
            "action": action, "forward": forwarded}


if __name__ == "__main__":
    run_service(app, SERVICE_HOST, VALIDATION_PORT,
                banner=f"Validation listening on {SERVICE_HOST}:{VALIDATION_PORT}, "
                       f"tolerance {VALIDATION_TOLERANCE:.0%}")
