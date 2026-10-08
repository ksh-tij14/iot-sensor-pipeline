"""Gateway: verifies chunks from sensor boards, countersigns them, forwards to the fork point.

Run from the repo root:  python -m gateway.gateway_service
"""

import logging
import os
import socket
import time

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from shared.api_models import SensorChunkIn
from shared.config import (FORK_URL, GATEWAY_PORT, GATEWAY_SECRET, MAX_CLOCK_SKEW_SECONDS,
                           RATE_LIMIT_BURST, RATE_LIMIT_PER_SECOND, load_keystore)
from shared.crypto_utils import sign
from shared.schemas import SignedChunk
from shared.service_utils import (RateLimiter, counter_tracker_from_env, install_malformed_handler,
                                  local_ip, log_event, reject, run_service)
from shared.verification import check_sensor_signature

HOP = "sensor-gateway"
FORWARD_TIMEOUT_SECONDS = 4.0  # below the board's 5 s HTTP timeout
# Which instance this is, when several run behind a load balancer (shown in logs
# and responses). Defaults to the hostname, which Docker sets to the container ID.
INSTANCE = os.environ.get("GATEWAY_INSTANCE", socket.gethostname())
# Optional HTTPS listener, used when this instance is reachable directly from the
# LAN (the boards' fallback address). Traffic through the load balancer arrives
# on GATEWAY_PORT and is rate-limited by nginx instead.
TLS_PORT = int(os.environ.get("GATEWAY_TLS_PORT", "0")) or None
TLS_CERT = os.environ.get("GATEWAY_TLS_CERT", "")
TLS_KEY = os.environ.get("GATEWAY_TLS_KEY", "")

log = logging.getLogger("gateway")
app = FastAPI(title="IoT gateway")
install_malformed_handler(app, log, HOP)

# In memory by default. Set GATEWAY_COUNTER_DB to a SQLite file path to share
# counters between gateway instances (see docker/README.md).
counters = counter_tracker_from_env("GATEWAY_COUNTER_DB")
limiter = RateLimiter(RATE_LIMIT_PER_SECOND, RATE_LIMIT_BURST) if RATE_LIMIT_PER_SECOND else None
_last_limit_log: dict[str, float] = {}


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    port = (request.scope.get("server") or (None, None))[1]
    client = request.client.host if request.client else "unknown"
    if limiter and port == TLS_PORT and not limiter.allow(client):
        if time.monotonic() - _last_limit_log.get(client, 0) > 10:   # one log line per client per 10 s
            _last_limit_log[client] = time.monotonic()
            log_event(log, logging.WARNING, "rate_limited", HOP, client=client, gateway=INSTANCE)
        return JSONResponse(status_code=429, content={"status": "rejected", "reason": "rate_limited"})
    return await call_next(request)


async def forward(chunk: SignedChunk) -> None:
    async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT_SECONDS) as client:
        response = await client.post(FORK_URL, content=chunk.to_json(),
                                     headers={"Content-Type": "application/json"})
        response.raise_for_status()


@app.post("/ingest")
async def ingest(incoming: SensorChunkIn, request: Request):
    chunk = incoming.to_chunk()
    problem = check_sensor_signature(chunk, load_keystore())  # re-read if the keystore changed
    if problem:
        return reject(log, HOP, request, 403 if problem == "revoked_sensor" else 401, problem,
                      incoming, gateway=INSTANCE)

    # Checked after the signature (so the timestamp is genuinely the device's)
    # and before the counter (so a stale chunk doesn't use up a counter value).
    skew = abs(time.time() * 1000 - chunk.timestamp) / 1000
    if skew > MAX_CLOCK_SKEW_SECONDS:
        return reject(log, HOP, request, 409, "stale_timestamp", incoming,
                      skew_seconds=round(skew, 1), gateway=INSTANCE)

    # check_and_record is atomic, so two concurrent requests can't both pass.
    if not counters.check_and_record(chunk.sensor_id, chunk.counter):
        return reject(log, HOP, request, 409, "stale_or_replayed_counter", incoming,
                      last_counter=counters.last_seen(chunk.sensor_id), gateway=INSTANCE)

    chunk.gateway_signature = sign(GATEWAY_SECRET, chunk.gateway_signing_bytes())

    try:
        await forward(chunk)
    except httpx.HTTPError as e:
        # The chunk was genuine, so this is an outage, not tampering. The counter
        # stays consumed: a resend of this chunk would be a replay.
        log_event(log, logging.ERROR, "forward_failed", HOP, sensor_id=chunk.sensor_id,
                  counter=chunk.counter, target=FORK_URL, gateway=INSTANCE, error=repr(e))
        return JSONResponse(status_code=502, content={"status": "forward_failed", "gateway": INSTANCE})

    log_event(log, logging.INFO, "accepted", HOP, sensor_id=chunk.sensor_id,
              counter=chunk.counter, gateway=INSTANCE, data=chunk.data)
    return {"status": "accepted", "counter": chunk.counter, "gateway": INSTANCE}


if __name__ == "__main__":
    if os.path.exists("/.dockerenv"):
        # Inside a container local_ip() is the container's own address, which the
        # board can't reach; it needs the host machine's LAN IP.
        where = ("Running in Docker: set GATEWAY_URL in firmware/src/main.cpp to\n"
                 "  https://<host machine's LAN IP>:8443/ingest  (see docker/README.md)")
    else:
        ip = local_ip()
        where = f"Local IP: {ip}"
    tls = (TLS_PORT, TLS_CERT, TLS_KEY) if TLS_PORT else None
    run_service(app, "0.0.0.0", GATEWAY_PORT, tls=tls, banner=(
        f"\nGateway listening on port {GATEWAY_PORT}" + (f" and HTTPS {TLS_PORT}" if tls else "") +
        f"\n{where}\nForwarding verified chunks to: {FORK_URL}\n"))
