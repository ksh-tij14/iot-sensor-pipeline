"""Virtual sensor board: a software stand-in for the ESP8266, for demos without hardware.

It behaves exactly like the firmware: every 5 s it takes a (simulated) DHT11
reading, increments a persisted counter, signs the canonical bytes with its own
ECDSA P-256 private key, and POSTs the chunk over HTTPS to the gateway, checking
the gateway's certificate. It goes through every check a real reading does.

It uses its own identity (esp32-002 by default), never the physical board's,
so the dashboard always shows which device a reading came from.

Run in Docker:  docker compose --profile demo up -d virtual-board
Run locally:    python -m tests.virtual_board --url https://localhost:8443/ingest --ca docker/certs/local/server.crt
"""

import argparse
import math
import os
import random
import time
from pathlib import Path

import httpx

from shared.config import load_sensor_private_keys
from shared.crypto_utils import ecdsa_sign
from shared.schemas import SignedChunk

INTERVAL_SECONDS = 5
# Counters for this identity start above anything earlier test runs used, and
# are persisted so a restart never reuses one (like the board's flash counter).
COUNTER_FLOOR = 3_000_000_000
COUNTER_JUMP = 10_000_000          # on "stale counter", skip ahead and retry


class Counter:
    def __init__(self, path: Path):
        self.path = path
        try:
            saved = int(path.read_text())
        except (OSError, ValueError):
            saved = 0
        self.value = max(saved, COUNTER_FLOOR)

    def next(self) -> int:
        """Increment and persist BEFORE the value is used, as the firmware does."""
        self.value += 1
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(str(self.value))
        return self.value

    def skip_ahead(self) -> None:
        self.value += COUNTER_JUMP


def simulated_reading(t: float) -> tuple[int, int]:
    """A plausible indoor room: slow 10-minute drift plus small noise, in DHT11-like steps."""
    temp = 29.0 + 1.5 * math.sin(2 * math.pi * t / 600) + random.uniform(-0.2, 0.2)
    hum = 55.0 - 4.0 * math.sin(2 * math.pi * t / 600) + random.uniform(-1, 1)
    return round(temp * 10) * 10, round(hum) * 100   # centi-units: 0.1 °C and 1 % resolution


def make_body(sensor_id: str, private_key: str, counter: int) -> dict:
    temp, hum = simulated_reading(time.time())
    chunk = SignedChunk(sensor_id=sensor_id, timestamp=int(time.time() * 1000), counter=counter,
                        data={"humidity_centi_pct": hum, "temp_centi_c": temp})
    chunk.sensor_signature = ecdsa_sign(private_key, chunk.signing_bytes())
    return {"sensor_id": chunk.sensor_id, "timestamp": chunk.timestamp, "counter": chunk.counter,
            "data": chunk.data, "sensor_signature": chunk.sensor_signature}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("VIRTUAL_BOARD_URL", "https://gateway-lb:8443/ingest"))
    ap.add_argument("--ca", default=os.environ.get("VIRTUAL_BOARD_CA", "/certs/server.crt"),
                    help="gateway certificate to trust (the board pins the same key)")
    ap.add_argument("--sensor-id", default=os.environ.get("VIRTUAL_BOARD_ID", "esp32-002"))
    ap.add_argument("--state", default=os.environ.get("VIRTUAL_BOARD_STATE", "/state/virtual_board_counter"))
    args = ap.parse_args()

    private_key = load_sensor_private_keys()[args.sensor_id]
    counter = Counter(Path(args.state))
    print(f"Virtual board {args.sensor_id} -> {args.url}, every {INTERVAL_SECONDS} s", flush=True)

    with httpx.Client(verify=args.ca, timeout=5.0) as client:
        while True:
            started = time.monotonic()
            for _ in range(50):
                body = make_body(args.sensor_id, private_key, counter.next())
                try:
                    r = client.post(args.url, json=body)
                except httpx.HTTPError as e:
                    print(f"counter={body['counter']} send failed: {e!r}", flush=True)
                    break
                if r.status_code == 409 and "counter" in r.text:
                    counter.skip_ahead()      # an earlier run used higher counters; catch up
                    continue
                t, h = body["data"]["temp_centi_c"] / 100, body["data"]["humidity_centi_pct"] / 100
                print(f"counter={body['counter']} temp={t:.1f}C hum={h:.0f}% -> HTTP {r.status_code}", flush=True)
                break
            time.sleep(max(0.0, INTERVAL_SECONDS - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
