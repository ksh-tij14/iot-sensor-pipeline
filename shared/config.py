"""Pipeline configuration. Plain Python so there are no extra dependencies."""

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# sensor_id -> {"public_key": hex, "revoked": bool}. Servers hold only public
# keys: each device's ECDSA private key exists on the device alone (written
# once into flash). A device marked "revoked" is rejected everywhere; the file
# is re-read when it changes, so revocation needs no restart.
# The committed gateway/keystore.json holds DEV keys for tests; a live setup
# points KEYSTORE_PATH at the keystore made by scripts/generate_secrets.py.
KEYSTORE_PATH = Path(os.environ.get("KEYSTORE_PATH", ROOT / "gateway" / "keystore.json"))

# Private keys of the *test* identities the attack simulator and benchmark sign
# with. Never contains a physical device's key.
SENSOR_KEYS_PATH = Path(os.environ.get("SENSOR_KEYS_PATH", ROOT / "tests" / "dev_sensor_keys.json"))

_keystore_cache: dict = {}


def load_keystore(path: Path = None) -> dict[str, dict]:
    path = Path(path or KEYSTORE_PATH)
    mtime = path.stat().st_mtime
    cached = _keystore_cache.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    keystore = {sid: {"public_key": e["public_key"], "revoked": bool(e.get("revoked", False))}
                for sid, e in raw.items()}
    _keystore_cache[path] = (mtime, keystore)
    return keystore


def load_sensor_private_keys(path: Path = None) -> dict[str, str]:
    with open(Path(path or SENSOR_KEYS_PATH), encoding="utf-8") as f:
        return json.load(f)


# A reading's timestamp must be within this many seconds of the server's
# clock. Devices sync via NTP, so honest drift is well under a second; 60 s
# leaves room for slow networks while making old captured packets useless
# even if replay-counter state were ever lost.
MAX_CLOCK_SKEW_SECONDS: int = 60


# How often an ESP32 batches readings into one SignedChunk.
# 5 s is a balance: near-real-time for dashboards, but few enough chunks that
# signing, Wi-Fi transmission and NVS counter writes (flash wear) stay cheap.
CHUNK_INTERVAL_SECONDS: int = 5

# Max relative difference when validation compares edge vs. cloud results
# (0.02 = 2%). Tolerance rather than exact equality, because floating-point
# and aggregation-order differences are expected and are not tampering.
VALIDATION_TOLERANCE: float = 0.02

# The gateway's own HMAC key for gateway_signature. Separate from every sensor
# key, so downstream stages can tell "passed the gateway" apart from "signed by
# a sensor". Dummy dev value; set GATEWAY_SECRET in the environment for real use.
GATEWAY_SECRET: bytes = os.environ.get("GATEWAY_SECRET", "dev-gateway-secret-change-me").encode("utf-8")

# Service ports. The gateway's must match GATEWAY_URL in firmware/src/main.cpp.
GATEWAY_PORT: int = 8001
FORK_PORT: int = 8002
EDGE_PORT: int = 8003
CLOUD_PORT: int = 8004
VALIDATION_PORT: int = 8005

# Where each stage sends its output. Defaults are for running everything on one
# machine; docker-compose overrides them with service names.
GATEWAY_URL: str = os.environ.get("GATEWAY_URL", f"http://127.0.0.1:{GATEWAY_PORT}/ingest")
FORK_URL: str = os.environ.get("FORK_URL", f"http://127.0.0.1:{FORK_PORT}/forward")
EDGE_URL: str = os.environ.get("EDGE_URL", f"http://127.0.0.1:{EDGE_PORT}")
CLOUD_URL: str = os.environ.get("CLOUD_URL", f"http://127.0.0.1:{CLOUD_PORT}")
VALIDATION_URL: str = os.environ.get("VALIDATION_URL", f"http://127.0.0.1:{VALIDATION_PORT}")

# Anomaly check in validation: flag a reading more than ANOMALY_STDDEV_THRESHOLD
# standard deviations from the mean of the last ANOMALY_WINDOW readings of the
# same type from the same sensor.
# - 20 readings = the last ~100 s at the 5 s interval: recent enough to follow
#   slow changes (a room warming up), long enough for a stable mean.
# - 3 standard deviations is the classic outlier threshold (~0.3% of normal
#   readings would exceed it by chance).
# - The DHT11 reports whole numbers, so in a stable room every recent reading is
#   identical and the standard deviation is 0, which would flag any 1-degree
#   change. The floor treats the spread as at least 1.0 unit (1 C or 1 %),
#   the sensor's own resolution.
# - No check until ANOMALY_MIN_HISTORY readings exist, since a mean of 1-2
#   values means nothing.
ANOMALY_WINDOW: int = 20
ANOMALY_STDDEV_THRESHOLD: float = 3.0
ANOMALY_MIN_STDDEV: float = 1.0
ANOMALY_MIN_HISTORY: int = 5

# Interface the internal services (fork/edge/cloud) bind to. Localhost by
# default so they aren't exposed on the network; Docker sets 0.0.0.0. The
# gateway always binds 0.0.0.0 because real ESP32s must reach it.
SERVICE_HOST: str = os.environ.get("SERVICE_HOST", "127.0.0.1")

# Per-client rate limit on network-facing entry points (requests/second and
# burst). A device sends one request every 5 s; 5/s with a burst of 20 leaves
# room for retries and demos while stopping floods. Unset = no limit (tests,
# local runs). The load balancer applies the same limit with nginx.
RATE_LIMIT_PER_SECOND: float = float(os.environ.get("RATE_LIMIT_PER_SECOND", "0")) or 0.0
RATE_LIMIT_BURST: int = int(os.environ.get("RATE_LIMIT_BURST", "20"))
