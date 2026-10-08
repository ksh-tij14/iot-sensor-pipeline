"""Small helpers shared by the HTTP services (gateway, fork, edge, cloud)."""

import json
import logging
import os
import socket
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from shared.events import record_event


def log_event(logger: logging.Logger, level: int, event: str, hop: str, **fields) -> None:
    """One JSON line per event, so logs are easy to grep and parse. Also
    recorded in the shared event store for the dashboard, if one is configured."""
    logger.log(level, json.dumps({"event": event, "hop": hop, "time": time.time(), **fields}))
    record_event(logger.name, event, hop, fields)


def reject(logger: logging.Logger, hop: str, request: Request, status: int, reason: str,
           chunk=None, **fields) -> JSONResponse:
    """Log a tamper event and return an error response. Callers must not forward."""
    if chunk is not None:
        fields.update(sensor_id=chunk.sensor_id, counter=chunk.counter)
    client = request.client.host if request.client else None
    log_event(logger, logging.WARNING, "tamper", hop, reason=reason, client=client, **fields)
    return JSONResponse(status_code=status, content={"status": "rejected", "reason": reason})


def install_malformed_handler(app: FastAPI, logger: logging.Logger, hop: str) -> None:
    """Turn request-validation errors into logged tamper events (HTTP 422)."""

    @app.exception_handler(RequestValidationError)
    async def malformed_chunk(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]
        return reject(logger, hop, request, 422, "malformed_chunk", errors=errors)


class CounterTracker:
    """Highest accepted counter per sensor. In memory, so it resets on restart
    and isn't shared between processes."""

    def __init__(self) -> None:
        self.last: dict[str, int] = {}

    def check_and_record(self, sensor_id: str, counter: int) -> bool:
        """True (and remember it) if counter is higher than any seen for this sensor."""
        last = self.last.get(sensor_id)
        if last is not None and counter <= last:
            return False
        self.last[sensor_id] = counter
        return True

    def last_seen(self, sensor_id: str) -> Optional[int]:
        return self.last.get(sensor_id)

    def clear(self) -> None:
        self.last.clear()


class SqliteCounterTracker:
    """Same as CounterTracker, but stored in a SQLite file, so several gateway
    instances sharing that file share one view of every sensor's counter (and
    it survives restarts). Without this, a chunk accepted by one instance could
    be replayed to another that has never seen it."""

    def __init__(self, path: str) -> None:
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS counters "
                       "(sensor_id TEXT PRIMARY KEY, counter INTEGER NOT NULL)")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)  # wait for the other instance's write

    def check_and_record(self, sensor_id: str, counter: int) -> bool:
        # One atomic statement: insert, or raise the stored counter only if the
        # new one is higher. If two instances race on the same counter, exactly
        # one of them changes the row.
        with closing(self._connect()) as db, db:
            cur = db.execute(
                "INSERT INTO counters VALUES (?, ?) ON CONFLICT(sensor_id) "
                "DO UPDATE SET counter = excluded.counter WHERE excluded.counter > counters.counter",
                (sensor_id, counter))
            return cur.rowcount == 1

    def last_seen(self, sensor_id: str) -> Optional[int]:
        with closing(self._connect()) as db:
            row = db.execute("SELECT counter FROM counters WHERE sensor_id = ?", (sensor_id,)).fetchone()
        return row[0] if row else None

    def clear(self) -> None:
        with closing(self._connect()) as db, db:
            db.execute("DELETE FROM counters")


def counter_tracker_from_env(env_var: str):
    """SQLite-backed tracker if env_var names a file, otherwise in-memory."""
    path = os.environ.get(env_var)
    return SqliteCounterTracker(path) if path else CounterTracker()


def local_ip() -> str:
    """IP of the network interface used for outbound traffic. UDP connect()
    sends no packets; it only makes the OS pick a route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class RateLimiter:
    """Token bucket per client: `rate` requests/second on average, bursts of up
    to `burst`. Memory is bounded by forgetting idle clients."""

    def __init__(self, rate: float, burst: int) -> None:
        self.rate, self.burst = rate, burst
        self.buckets: dict[str, tuple[float, float]] = {}   # client -> (tokens, last time)

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        tokens, last = self.buckets.get(client, (float(self.burst), now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        allowed = tokens >= 1
        self.buckets[client] = (tokens - 1 if allowed else tokens, now)
        if len(self.buckets) > 10000:                        # drop clients idle for over a minute
            self.buckets = {c: v for c, v in self.buckets.items() if now - v[1] < 60}
        return allowed


def run_service(app: FastAPI, host: str, port: int, banner: Optional[str] = None,
                tls: Optional[tuple[int, str, str]] = None) -> None:
    """Serve on host:port, and optionally also over HTTPS on (port, certfile, keyfile)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if banner:
        print(banner)
    if not tls:
        uvicorn.run(app, host=host, port=port, log_level="warning")
        return
    tls_port, certfile, keyfile = tls
    servers = [uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning")),
               uvicorn.Server(uvicorn.Config(app, host=host, port=tls_port, log_level="warning",
                                             ssl_certfile=certfile, ssl_keyfile=keyfile))]
    import asyncio

    async def serve_all():
        await asyncio.gather(*(s.serve() for s in servers))

    asyncio.run(serve_all())
