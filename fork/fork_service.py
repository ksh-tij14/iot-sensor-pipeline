"""Fork point: re-verifies both signatures, sends each chunk to BOTH edge and
cloud, then hands their two results to the validation service.

Edge and cloud process the same stream independently; a shared chunk_id lets
their results be matched back together.

Run from the repo root:  python -m fork.fork_service
"""

import asyncio
import logging
import uuid

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from shared.api_models import GatewayChunkIn
from shared.config import (CLOUD_URL, EDGE_URL, FORK_PORT, GATEWAY_SECRET, SERVICE_HOST,
                           VALIDATION_URL, load_keystore)
from shared.crypto_utils import verify
from shared.service_utils import (counter_tracker_from_env, install_malformed_handler, log_event,
                                  reject, run_service)
from shared.verification import check_sensor_signature

HOP = "gateway-fork"
# Processing + validation must finish inside the gateway's 4 s timeout.
FORWARD_TIMEOUT_SECONDS = 1.5
VALIDATE_TIMEOUT_SECONDS = 2.0
TARGETS = {"cloud": f"{CLOUD_URL}/process", "edge": f"{EDGE_URL}/process"}

log = logging.getLogger("fork")
app = FastAPI(title="IoT fork point")
install_malformed_handler(app, log, HOP)

# The gateway already rejects replays, but anyone who can reach the fork could
# resend a captured, validly signed chunk, so the fork checks too. Persisted
# when FORK_COUNTER_DB is set, so a fork restart doesn't reopen replays.
counters = counter_tracker_from_env("FORK_COUNTER_DB")


async def send(client: httpx.AsyncClient, url: str, payload: dict) -> dict:
    response = await client.post(url, json=payload)
    response.raise_for_status()
    return response.json()


async def forward_to_all(payload: dict) -> dict[str, dict]:
    """Send to cloud and edge in parallel. Returns {target: its response, or {"error": ...}}."""
    async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT_SECONDS) as client:
        results = await asyncio.gather(*(send(client, url, payload) for url in TARGETS.values()),
                                       return_exceptions=True)
    return {name: {"error": repr(r)} if isinstance(r, Exception) else r
            for name, r in zip(TARGETS, results)}


async def validate(body: dict) -> dict:
    async with httpx.AsyncClient(timeout=VALIDATE_TIMEOUT_SECONDS) as client:
        response = await client.post(f"{VALIDATION_URL}/validate", json=body)
        response.raise_for_status()
        return response.json()


@app.post("/forward")
async def forward(incoming: GatewayChunkIn, request: Request):
    chunk = incoming.to_chunk()

    # 1. Did this come from the gateway, unmodified?
    if not verify(GATEWAY_SECRET, chunk.gateway_signing_bytes(), chunk.gateway_signature):
        return reject(log, HOP, request, 401, "bad_gateway_signature", incoming)

    # 2. End-to-end: does the device's own ECDSA signature still hold? The
    #    gateway vouched for this chunk, so a failure here means the data was
    #    changed after the gateway verified it. Gateways hold only public keys,
    #    so even a fully compromised gateway can't forge a valid device signature.
    problem = check_sensor_signature(chunk, load_keystore())
    if problem == "revoked_sensor":
        return reject(log, HOP, request, 403, "revoked_sensor", incoming)
    if problem:
        return reject(log, HOP, request, 401, "gateway-tampered-after-verification", incoming,
                      detail=problem)

    if not counters.check_and_record(chunk.sensor_id, chunk.counter):
        return reject(log, HOP, request, 409, "stale_or_replayed_counter", incoming,
                      last_counter=counters.last_seen(chunk.sensor_id))

    # Verification ends here: edge and cloud get the plain reading plus a
    # chunk_id to match their results by.
    payload = {
        "chunk_id": str(uuid.uuid4()),
        "sensor_id": chunk.sensor_id,
        "timestamp": chunk.timestamp,
        "counter": chunk.counter,
        "data": chunk.data,
        # Kept with the cloud's backup so recovery can re-verify it.
        "sensor_signature": chunk.sensor_signature,
    }
    results = await forward_to_all(payload)
    failed = {name: r["error"] for name, r in results.items() if "error" in r}
    if failed:
        # Without both results there is nothing to validate.
        log_event(log, logging.ERROR, "forward_failed", HOP, chunk_id=payload["chunk_id"],
                  sensor_id=chunk.sensor_id, counter=chunk.counter, failed=failed)
        return JSONResponse(status_code=502, content={"status": "forward_failed",
                                                      "chunk_id": payload["chunk_id"],
                                                      "results": results})

    try:
        validation = await validate({
            "chunk_id": payload["chunk_id"],
            "sensor_id": chunk.sensor_id,
            "cloud_result": results["cloud"].get("result"),
            "edge_result": results["edge"].get("result"),
        })
    except httpx.HTTPError as e:
        log_event(log, logging.ERROR, "validation_unreachable", HOP, chunk_id=payload["chunk_id"],
                  sensor_id=chunk.sensor_id, counter=chunk.counter, error=repr(e))
        return JSONResponse(status_code=502, content={"status": "validation_unreachable",
                                                      "chunk_id": payload["chunk_id"],
                                                      "results": results})

    log_event(log, logging.INFO, "forwarded", HOP, chunk_id=payload["chunk_id"],
              sensor_id=chunk.sensor_id, counter=chunk.counter,
              validation=validation.get("status"))
    return {"status": "forwarded", "chunk_id": payload["chunk_id"], "results": results,
            "validation": validation}


if __name__ == "__main__":
    run_service(app, SERVICE_HOST, FORK_PORT,
                banner=f"Fork listening on {SERVICE_HOST}:{FORK_PORT}, sending to {TARGETS}")
