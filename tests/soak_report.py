"""Long-run (soak) report for one device, from the shared event log.

Leave the board running for a while, then:

    cd docker
    docker compose exec dashboard python -m tests.soak_report --hours 1

Reports readings delivered vs expected, gaps, counter values skipped (failed
sends), and how many readings were validated end to end. --json for the paper.
"""

import argparse
import json
import os
import time

from shared.config import CHUNK_INTERVAL_SECONDS
from shared.events import read_events

INTERVAL_SECONDS = CHUNK_INTERVAL_SECONDS


def soak_report(path: str, sensor_id: str, hours: float, now: float = None) -> dict:
    now = now or time.time()
    since = now - hours * 3600
    accepted = [e for e in read_events(path, limit=1_000_000, events=["accepted"], sensor_id=sensor_id)
                if e["time"] >= since]
    accepted.sort(key=lambda e: e["time"])
    validated = [e for e in read_events(path, limit=1_000_000, events=["validated"], sensor_id=sensor_id)
                 if e["time"] >= since]
    rejected = [e for e in read_events(path, limit=1_000_000, events=["tamper"], sensor_id=sensor_id)
                if e["time"] >= since]
    if not accepted:
        return {"sensor_id": sensor_id, "hours": hours, "accepted": 0, "note": "no readings in this window"}

    span = accepted[-1]["time"] - accepted[0]["time"]
    expected = int(span // INTERVAL_SECONDS) + 1
    gaps = [b["time"] - a["time"] for a, b in zip(accepted, accepted[1:])]
    long_gaps = [g for g in gaps if g > 2 * INTERVAL_SECONDS]
    counters = [e["counter"] for e in accepted if e.get("counter") is not None]
    skipped = sum(max(0, b - a - 1) for a, b in zip(counters, counters[1:]))
    return {
        "sensor_id": sensor_id,
        "window_hours": hours,
        "observed_minutes": round(span / 60, 1),
        "accepted": len(accepted),
        "expected": expected,
        "delivery_rate": round(len(accepted) / expected, 4),
        "validated": len(validated),
        "rejected": len(rejected),
        "gaps_over_2_intervals": len(long_gaps),
        "longest_gap_s": round(max(gaps), 1) if gaps else 0.0,
        "counter_values_skipped": skipped,   # consumed by failed sends: allowed, never reused
        "counter_monotonic": all(b > a for a, b in zip(counters, counters[1:])),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hours", type=float, default=1.0)
    ap.add_argument("--device", default=os.environ.get("DEVICE_ID", "esp32-001"))
    ap.add_argument("--db", default=os.environ.get("EVENT_DB_PATH", "/events/events.db"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    r = soak_report(args.db, args.device, args.hours)
    if args.json:
        print(json.dumps(r, indent=2))
        return
    for k, v in r.items():
        print(f"{k:24} {v}")


if __name__ == "__main__":
    main()
