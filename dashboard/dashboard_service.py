"""Dashboard: a web page showing the pipeline live, plus a small API behind it.

It only reads: readings and results from the cloud, events from the shared
event store, and health from each service. The one thing it can trigger is
the attack simulator, against the running pipeline.

Run from the repo root:  python -m dashboard.dashboard_service   (http://localhost:8080)
"""

import asyncio
import os
import threading
import time
from pathlib import Path
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from shared.config import CHUNK_INTERVAL_SECONDS, CLOUD_URL, EDGE_URL, FORK_URL, GATEWAY_URL, SERVICE_HOST, VALIDATION_URL
from shared.events import count_events, read_events, verify_chain
from shared.service_utils import run_service
from tests import attack_simulator, benchmark

DASHBOARD_PORT = 8080
STATIC = Path(__file__).parent / "static"
EVENT_DB_PATH = os.environ.get("EVENT_DB_PATH", "")
DEVICE_ID = os.environ.get("DEVICE_ID", "esp32-001")   # the physical sensor board
VIRTUAL_DEVICE_ID = os.environ.get("VIRTUAL_DEVICE_ID", "esp32-002")  # tests/virtual_board.py
DEVICE_ONLINE_SECONDS = max(8, 4 * CHUNK_INTERVAL_SECONDS)   # 4 missed intervals = offline
# The devices the dashboard can show. Attack-simulator traffic (its own identity) never appears here.
DEVICES = {DEVICE_ID: "physical", VIRTUAL_DEVICE_ID: "virtual"}


def _base(url: str) -> str:
    return url.split("/", 3)[0] + "//" + url.split("/", 3)[2]


# name=base-url pairs to health-check. Docker overrides this with every container.
HEALTH_TARGETS = dict(pair.split("=", 1) for pair in os.environ.get(
    "HEALTH_TARGETS",
    f"gateway={_base(GATEWAY_URL)},fork={_base(FORK_URL)},edge={EDGE_URL},"
    f"cloud={CLOUD_URL},validation={VALIDATION_URL}").split(","))

ATTACKS = {
    "corruption": ("Packet corruption", attack_simulator.simulate_packet_corruption),
    "injection": ("Packet injection", attack_simulator.simulate_packet_injection),
    "gateway_tamper": ("Gateway tamper after verification", attack_simulator.simulate_gateway_tamper_after_verification),
    "stale_timestamp": ("Delayed delivery (stale timestamp)", attack_simulator.simulate_stale_timestamp),
    "node_tamper": ("Compromised processing node", attack_simulator.simulate_processing_node_tamper),
    "replay": ("Replay attack", attack_simulator.simulate_replay_attack),
    "duplication": ("Packet duplication", attack_simulator.simulate_packet_duplication),
    "delay": ("Packet delay", attack_simulator.simulate_packet_delay),
    "dropping": ("Packet dropping", attack_simulator.simulate_packet_dropping),
}
_attack_lock = threading.Lock()  # the simulator's counter isn't thread-safe
attack_history: list[dict] = []  # results of attacks run from this dashboard, newest first

app = FastAPI(title="IoT pipeline dashboard")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

@app.middleware("http")
async def no_stale_frontend(request: Request, call_next):
    """Browsers must revalidate the page and its scripts, so an update shows up on reload."""
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


ACTION_HEADER = "X-Dashboard-Action"


def require_action_header(request: Request) -> None:
    """Block cross-site requests to the actions. A page on another site can make
    a browser send a plain POST to localhost, but not one with a custom header
    (that needs a CORS preflight, which this server never approves)."""
    if request.headers.get(ACTION_HEADER) != "1":
        raise HTTPException(403, f"missing {ACTION_HEADER} header")


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


async def fetch_results(limit: int, sensor_id: Optional[str]) -> Optional[list]:
    params = {"limit": limit, **({"sensor_id": sensor_id} if sensor_id else {})}
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(f"{CLOUD_URL}/results/recent", params=params)
            r.raise_for_status()
            return r.json()
    except httpx.HTTPError:
        return None  # cloud unreachable


def _device(device: Optional[str]) -> str:
    if device is None:
        return DEVICE_ID
    if device not in DEVICES:
        raise HTTPException(400, f"device must be one of {list(DEVICES)}")
    return device


def _last_seen(sensor_id: str) -> Optional[float]:
    last = read_events(EVENT_DB_PATH, limit=1, events=["accepted"], sensor_id=sensor_id)
    return last[0]["time"] if last else None


def _is_online(last_seen: Optional[float]) -> bool:
    return last_seen is not None and time.time() - last_seen < DEVICE_ONLINE_SECONDS


@app.get("/api/devices")
async def devices():
    out = []
    for sensor_id, kind in DEVICES.items():
        seen = _last_seen(sensor_id)
        out.append({"sensor_id": sensor_id, "kind": kind, "last_seen": seen, "online": _is_online(seen)})
    return {"devices": out}


@app.get("/api/overview")
async def overview(device: Optional[str] = None):
    sensor_id = _device(device)
    counts = count_events(EVENT_DB_PATH)
    by_event, by_hop = counts["by_event"], counts["by_event_hop"]
    # Reading counts are for the selected device only, not attack-simulator traffic.
    device_counts = count_events(EVENT_DB_PATH, sensor_id=sensor_id)["by_event"]
    latest = await fetch_results(1, sensor_id)
    last_seen = _last_seen(sensor_id)
    return {
        "device": {
            "sensor_id": sensor_id,
            "kind": DEVICES[sensor_id],
            "last_seen": last_seen,
            "online": _is_online(last_seen),
            "latest": latest[0] if latest else None,
        },
        "cloud_reachable": latest is not None,
        "counts": {
            "accepted": device_counts.get("accepted", 0),
            "validated": device_counts.get("validated", 0),
            "tamper": by_event.get("tamper", 0),
            "anomalies": by_event.get("anomaly", 0),
            "mismatches": by_event.get("validation_failed", 0),
            "recoveries": by_event.get("recovered", 0),
            "quarantined": by_event.get("quarantined", 0),
            "rate_limited": by_event.get("rate_limited", 0),
            "forward_failures": by_event.get("forward_failed", 0),
        },
        "tamper_by_hop": {k.split("|", 1)[1]: v for k, v in by_hop.items() if k.startswith("tamper|")},
    }


@app.get("/api/readings")
async def readings(device: Optional[str] = None, limit: int = 60):
    rows = await fetch_results(max(1, min(limit, 500)), _device(device))
    return {"cloud_reachable": rows is not None, "readings": list(reversed(rows or []))}


EVENT_KINDS = {
    "all": None,
    "accepted": ["accepted"],
    "tamper": ["tamper"],
    "validated": ["validated"],
    "anomaly": ["anomaly"],
    "recovery": ["validation_failed", "recovered", "quarantined"],
    "failures": ["forward_failed", "validation_unreachable", "final_forward_failed"],
}


@app.get("/api/events")
async def events(kind: str = "all", limit: int = 100, after_id: int = 0):
    if kind not in EVENT_KINDS:
        raise HTTPException(400, f"kind must be one of {list(EVENT_KINDS)}")
    return read_events(EVENT_DB_PATH, limit=max(1, min(limit, 500)), events=EVENT_KINDS[kind], after_id=after_id)


@app.get("/api/health")
async def health():
    async def check(name: str, base: str) -> dict:
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=1.5) as client:
                ok = (await client.get(f"{base}/docs")).status_code == 200
        except httpx.HTTPError:
            ok = False
        return {"name": name, "url": base, "ok": ok, "ms": round((time.perf_counter() - start) * 1000)}
    return await asyncio.gather(*(check(n, u) for n, u in HEALTH_TARGETS.items()))


@app.get("/api/attacks")
async def list_attacks():
    return {"attacks": [{"key": k, "name": n} for k, (n, _) in ATTACKS.items()], "history": attack_history[:30]}


def _run_attack(key: str) -> dict:
    name, func = ATTACKS[key]
    start = time.perf_counter()
    with _attack_lock:
        try:
            detail, passed = func(), True
        except attack_simulator.Unreachable as e:
            detail, passed = f"SKIPPED: {e}", True
        except AssertionError as e:
            detail, passed = f"NOT CAUGHT: {e}", False
        except httpx.HTTPError as e:
            detail, passed = f"ERROR: {e!r}", False
    result = {"key": key, "name": name, "passed": passed, "detail": detail,
              "duration_ms": round((time.perf_counter() - start) * 1000), "time": time.time()}
    attack_history.insert(0, result)
    del attack_history[100:]
    return result


@app.post("/api/attacks/{key}", dependencies=[Depends(require_action_header)])
async def run_attack(key: str):
    if key not in ATTACKS:
        raise HTTPException(404, f"unknown attack {key!r}")
    return await run_in_threadpool(_run_attack, key)


@app.post("/api/attacks", dependencies=[Depends(require_action_header)])
async def run_all_attacks():
    results = [await run_in_threadpool(_run_attack, key) for key in ATTACKS]
    return {"passed": sum(r["passed"] for r in results), "total": len(results), "results": results}


@app.get("/api/events/verify")
async def verify_events():
    """Recompute the event log's hash chain; reports the first broken entry, if any."""
    return await run_in_threadpool(verify_chain, EVENT_DB_PATH)


_benchmark_lock = threading.Lock()


def _run_benchmark(genuine: int, runs: int) -> dict:
    with _benchmark_lock, _attack_lock:
        return benchmark.run_benchmark(genuine=genuine, runs=runs)


@app.post("/api/benchmark", dependencies=[Depends(require_action_header)])
async def run_benchmark(genuine: int = 30, runs: int = 3):
    return await run_in_threadpool(_run_benchmark, max(1, min(genuine, 500)), max(1, min(runs, 50)))


if __name__ == "__main__":
    run_service(app, SERVICE_HOST, DASHBOARD_PORT,
                banner=f"Dashboard on http://{SERVICE_HOST}:{DASHBOARD_PORT}  (device {DEVICE_ID})")
