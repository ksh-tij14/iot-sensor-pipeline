"""Benchmark: measure detection and latency against the live pipeline.

Sends N genuine readings and K runs of each detectable attack, then reports:
- detection rate per attack and overall (true-positive rate / recall),
- false-positive rate (genuine readings wrongly rejected),
- precision and F1,
- end-to-end latency of genuine readings (gateway -> fork -> edge + cloud ->
  validation -> final storage; the gateway only answers once all of it is done).

From the repo root, with the pipeline running:
    python -m tests.benchmark --genuine 100 --runs 10 [--json results.json]
"""

import argparse
import json
import statistics
import sys
import time

import httpx

from tests import attack_simulator as sim

ATTACKS = {
    "Packet corruption": sim.simulate_packet_corruption,
    "Packet injection": sim.simulate_packet_injection,
    "Replay": sim.simulate_replay_attack,
    "Duplication": sim.simulate_packet_duplication,
    "Delay / reorder": sim.simulate_packet_delay,
    "Delayed delivery (stale timestamp)": sim.simulate_stale_timestamp,
    "Gateway tamper after verification": sim.simulate_gateway_tamper_after_verification,
    "Compromised processing node": sim.simulate_processing_node_tamper,
}


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(p / 100 * (len(ordered) - 1)))]


def run_benchmark(genuine: int = 50, runs: int = 5, replay_wait: float = 0.0) -> dict:
    started = time.time()
    latencies, false_positives, genuine_errors = [], 0, []
    for _ in range(genuine):
        body = sim.sensor_body(sim.make_chunk(sim.next_counter()))
        t0 = time.perf_counter()
        r = sim.post_json(sim.GATEWAY_URL, body)
        elapsed = (time.perf_counter() - t0) * 1000
        if r.status_code == 200:
            latencies.append(elapsed)
        else:
            false_positives += 1
            genuine_errors.append(f"{r.status_code} {r.text[:100]}")

    original_sleep = time.sleep
    if replay_wait < 2:     # the replay attack waits 2 s by default; shorten it for benchmarking
        sim.time.sleep = lambda s: original_sleep(min(s, replay_wait))
    per_attack = {}
    try:
        for name, attack in ATTACKS.items():
            detected = skipped = 0
            for _ in range(runs):
                try:
                    attack()
                    detected += 1
                except sim.Unreachable:
                    skipped += 1
                except (AssertionError, httpx.HTTPError):
                    pass
            tried = runs - skipped
            per_attack[name] = {"runs": tried, "detected": detected,
                                "detection_rate": round(detected / tried, 4) if tried else None,
                                **({"skipped": skipped} if skipped else {})}
    finally:
        sim.time.sleep = original_sleep

    tp = sum(a["detected"] for a in per_attack.values())
    total_attacks = sum(a["runs"] for a in per_attack.values())
    fn = total_attacks - tp
    fp = false_positives
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / total_attacks if total_attacks else 0.0
    return {
        "genuine": {"sent": genuine, "accepted": len(latencies), "false_positives": fp,
                    "false_positive_rate": round(fp / genuine, 4) if genuine else 0.0,
                    "errors": genuine_errors[:5]},
        "latency_ms": {"mean": round(statistics.fmean(latencies), 1) if latencies else None,
                       "p50": round(percentile(latencies, 50), 1), "p95": round(percentile(latencies, 95), 1),
                       "p99": round(percentile(latencies, 99), 1), "max": round(max(latencies), 1) if latencies else None},
        "attacks": per_attack,
        "overall": {"attacks_sent": total_attacks, "detected": tp, "missed": fn,
                    "detection_rate": round(recall, 4), "precision": round(precision, 4),
                    "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0},
        "duration_s": round(time.time() - started, 1),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--genuine", type=int, default=100, help="genuine readings to send")
    parser.add_argument("--runs", type=int, default=10, help="runs of each attack")
    parser.add_argument("--json", help="also write the results to this file")
    args = parser.parse_args()

    r = run_benchmark(args.genuine, args.runs)
    g, lat, o = r["genuine"], r["latency_ms"], r["overall"]
    print(f"Genuine readings: {g['accepted']}/{g['sent']} accepted, false-positive rate {g['false_positive_rate']:.1%}")
    print(f"Latency (ms): mean {lat['mean']}  p50 {lat['p50']}  p95 {lat['p95']}  p99 {lat['p99']}  max {lat['max']}\n")
    print(f"{'Attack':<38}{'Detected':>10}{'Rate':>8}")
    for name, a in r["attacks"].items():
        rate = "skip" if a["detection_rate"] is None else f"{a['detection_rate']:.0%}"
        print(f"{name:<38}{a['detected']:>5}/{a['runs']:<4}{rate:>8}")
    print(f"\nOverall: detection rate {o['detection_rate']:.1%}, precision {o['precision']:.1%}, "
          f"F1 {o['f1']:.3f}  ({r['duration_s']} s)")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=2)
    return 0 if o["missed"] == 0 and g["false_positives"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
