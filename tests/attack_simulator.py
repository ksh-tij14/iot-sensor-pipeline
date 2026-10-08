"""Attack simulator: sends crafted HTTP requests straight to the live pipeline
to check that each defence works. No board needed; this tests the security
boundaries themselves rather than interfering with real WiFi packets.

Attacks 1-8 are script-driven. Attack 9 (packet dropping) is checked too, but
is best demonstrated live with the real board: move it out of WiFi range for
an interval and show the pipeline carries on.

Start the pipeline first (see README), then from the repo root:
    python -m tests.attack_simulator                # all 9
    python -m tests.attack_simulator --script-only  # 1-8 only (used by CI)

Signs as test identity esp32-003 (key from SENSOR_KEYS_PATH), never as the
physical board. Attack 8 needs the cloud and validation services reachable;
from outside Docker it's reported as SKIP.
"""

import argparse
import json
import os
import sys
import time
from typing import Callable

import httpx

from shared.config import (CLOUD_URL, FORK_URL, GATEWAY_SECRET, GATEWAY_URL, VALIDATION_URL,
                           load_sensor_private_keys)
from shared.crypto_utils import ecdsa_sign, sign
from shared.schemas import SignedChunk

SENSOR_ID = "esp32-003"
PRIVATE_KEY = load_sensor_private_keys()[SENSOR_ID]
TIMEOUT = 10.0

# Counters follow the clock: 100 per second since a fixed point, above every
# counter earlier versions used. Each call takes the larger of "previous + 1"
# and "the clock's value now", so a long-running process (the dashboard) never
# falls behind counters that later, separate runs have already used. Callers
# use far fewer than 100 counters per second. Stays inside the firmware's
# uint32 until about late 2027; after that, rotate keys (new identities).
_last_counter = 0


def _clock_counter() -> int:
    return 1_000_000_000 + int((time.time() - 1_790_000_000) * 100)


class Unreachable(Exception):
    """A service this attack needs isn't reachable from here."""


def next_counter() -> int:
    global _last_counter
    _last_counter = max(_last_counter + 1, _clock_counter())
    return _last_counter


def make_chunk(counter: int, temp_centi_c: int = 2400, age_seconds: float = 0) -> SignedChunk:
    """A genuine chunk, signed exactly as the board's firmware signs it."""
    chunk = SignedChunk(sensor_id=SENSOR_ID, timestamp=int((time.time() - age_seconds) * 1000), counter=counter,
                        data={"humidity_centi_pct": 5500, "temp_centi_c": temp_centi_c})
    chunk.sensor_signature = ecdsa_sign(PRIVATE_KEY, chunk.signing_bytes())
    return chunk


def sensor_body(chunk: SignedChunk) -> dict:
    """What the board sends: everything except gateway_signature."""
    return {k: v for k, v in json.loads(chunk.to_json()).items() if k != "gateway_signature"}


def post_json(url: str, body: dict) -> httpx.Response:
    return httpx.post(url, json=body, timeout=TIMEOUT)


def post_raw(url: str, raw: bytes) -> httpx.Response:
    return httpx.post(url, content=raw, headers={"Content-Type": "application/json"}, timeout=TIMEOUT)


def passed_gateway(r: httpx.Response) -> bool:
    """The gateway accepted the chunk. A 502 forward_failed still means it passed
    every gateway check (only a later stage was unreachable)."""
    return r.status_code == 200 or (r.status_code == 502 and r.json().get("status") == "forward_failed")


def expect_rejected(r: httpx.Response, status: int, reason: str) -> str:
    body = r.json()
    assert r.status_code == status and body.get("reason") == reason, \
        f"expected {status} {reason!r}, got {r.status_code} {body}"
    return f"rejected: {status} {reason}"


# --- the attacks ---------------------------------------------------------------

def simulate_packet_corruption() -> str:
    """A validly shaped, correctly signed chunk with one byte of its data flipped in transit."""
    raw = json.dumps(sensor_body(make_chunk(next_counter()))).encode()
    # Flip the lowest bit of the first digit of the temperature value. XOR 1 on
    # an ASCII digit gives another digit ('4' -> '5'), so the JSON stays valid
    # and only the signature check can catch it.
    i = raw.index(b'"temp_centi_c": ') + len(b'"temp_centi_c": ')
    corrupted = raw[:i] + bytes([raw[i] ^ 0x01]) + raw[i + 1:]
    return expect_rejected(post_raw(GATEWAY_URL, corrupted), 401, "bad_sensor_signature")


def simulate_replay_attack() -> str:
    """Capture a genuine chunk, wait, then resend it unchanged (same counter)."""
    captured = sensor_body(make_chunk(next_counter()))
    first = post_json(GATEWAY_URL, captured)
    assert passed_gateway(first), f"genuine chunk not accepted: {first.status_code} {first.text}"
    time.sleep(2)  # the attacker replays it later
    return expect_rejected(post_json(GATEWAY_URL, captured), 409, "stale_or_replayed_counter")


def simulate_packet_injection() -> str:
    """A forged chunk with a made-up signature, not made with the device's private key."""
    forged = sensor_body(make_chunk(next_counter(), temp_centi_c=1500))
    forged["sensor_signature"] = os.urandom(64).hex()
    return expect_rejected(post_json(GATEWAY_URL, forged), 401, "bad_sensor_signature")


def simulate_packet_duplication() -> str:
    """The same genuine chunk sent twice in a row."""
    body = sensor_body(make_chunk(next_counter()))
    first = post_json(GATEWAY_URL, body)
    assert passed_gateway(first), f"genuine chunk not accepted: {first.status_code} {first.text}"
    return expect_rejected(post_json(GATEWAY_URL, body), 409, "stale_or_replayed_counter")


def simulate_packet_delay() -> str:
    """An older chunk arrives after a newer one was already accepted."""
    delayed = make_chunk(next_counter())   # created first...
    newer = make_chunk(next_counter())
    first = post_json(GATEWAY_URL, sensor_body(newer))  # ...but the newer one arrives first
    assert passed_gateway(first), f"newer chunk not accepted: {first.status_code} {first.text}"
    return expect_rejected(post_json(GATEWAY_URL, sensor_body(delayed)), 409,
                           "stale_or_replayed_counter")


def simulate_stale_timestamp() -> str:
    """A genuine, correctly signed chunk held back for 10 minutes and delivered
    with a counter the gateway hasn't seen yet. The counter alone can't catch
    it; the timestamp window does (this is also what protects if counter state
    were ever lost)."""
    stale = make_chunk(next_counter(), age_seconds=600)
    return expect_rejected(post_json(GATEWAY_URL, sensor_body(stale)), 409, "stale_timestamp")


def simulate_gateway_tamper_after_verification() -> str:
    """A compromised gateway alters the reading after verifying it and re-signs
    as the gateway (it has the gateway key, and even the whole keystore - which
    now holds only public keys). The fork's end-to-end check of the device's
    ECDSA signature catches it."""
    chunk = make_chunk(next_counter())
    chunk.data["temp_centi_c"] = 4500                     # altered after verification
    chunk.gateway_signature = sign(GATEWAY_SECRET, chunk.gateway_signing_bytes())  # valid
    return expect_rejected(post_raw(FORK_URL, chunk.to_json().encode()), 401,
                           "gateway-tampered-after-verification")


def simulate_processing_node_tamper() -> str:
    """A compromised edge node returns a wrong result for a genuine reading.
    Validation must catch the disagreement, verify the cloud's signed backup,
    and restore the correct result from it."""
    try:
        r = post_json(GATEWAY_URL, sensor_body(make_chunk(next_counter())))
        assert r.status_code == 200, f"genuine chunk not accepted: {r.status_code} {r.text}"
        latest = httpx.get(f"{CLOUD_URL}/results/recent", params={"sensor_id": SENSOR_ID, "limit": 1},
                           timeout=TIMEOUT).json()[0]
        true_result = latest["result"]
        assert true_result, "the genuine reading has no validated result"
        doctored = dict(true_result, temp_c=true_result["temp_c"] + 15)
        v = httpx.post(f"{VALIDATION_URL}/validate", timeout=TIMEOUT, json={
            "chunk_id": latest["chunk_id"], "sensor_id": SENSOR_ID,
            "cloud_result": true_result, "edge_result": doctored}).json()
    except httpx.ConnectError as e:
        raise Unreachable(f"cloud/validation not reachable from here ({e!r})")
    assert v.get("status") == "mismatch", f"mismatch not detected: {v}"
    assert v.get("recovered") is True and v.get("result") == true_result, f"not recovered: {v}"
    return "mismatch caught at edge-cloud-validation; backup signature verified; correct result restored"


def simulate_packet_dropping() -> str:
    """One interval's chunk never arrives. Expected, tolerated behaviour, not a
    caught attack: the counter just has a gap and the pipeline carries on."""
    before = next_counter()
    dropped = next_counter()  # never sent
    after = next_counter()
    r1 = post_json(GATEWAY_URL, sensor_body(make_chunk(before)))
    assert passed_gateway(r1), f"chunk before the gap not accepted: {r1.status_code} {r1.text}"
    r2 = post_json(GATEWAY_URL, sensor_body(make_chunk(after)))
    assert r2.status_code == 200, f"pipeline didn't accept the chunk after the gap: {r2.status_code} {r2.text}"
    return f"tolerated: counter {dropped} missing, pipeline still accepting (HTTP 200)"


SCRIPT_ATTACKS: list[tuple[str, Callable[[], str]]] = [
    ("1. Packet corruption", simulate_packet_corruption),
    ("2. Replay attack", simulate_replay_attack),
    ("3. Packet injection", simulate_packet_injection),
    ("4. Packet duplication", simulate_packet_duplication),
    ("5. Packet delay", simulate_packet_delay),
    ("6. Delayed delivery (stale timestamp)", simulate_stale_timestamp),
    ("7. Gateway tamper after verification", simulate_gateway_tamper_after_verification),
    ("8. Compromised processing node", simulate_processing_node_tamper),
]
LIVE_DEMO_ATTACKS = [("9. Packet dropping", simulate_packet_dropping)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--script-only", action="store_true",
                        help="run only attacks 1-8 (skip the dropout test, which is meant for the live demo)")
    args = parser.parse_args()
    attacks = SCRIPT_ATTACKS if args.script_only else SCRIPT_ATTACKS + LIVE_DEMO_ATTACKS

    for name, url in [("gateway", GATEWAY_URL), ("fork", FORK_URL)]:
        try:
            httpx.get(url.rsplit("/", 1)[0] + "/docs", timeout=2)
        except httpx.HTTPError:
            print(f"Can't reach the {name} at {url}. Start the pipeline first (see README).")
            return 1

    results = []
    for name, attack in attacks:
        try:
            detail, status = attack(), "PASS"
        except Unreachable as e:
            detail, status = str(e), "SKIP"
        except AssertionError as e:
            detail, status = f"NOT CAUGHT: {e}", "FAIL"
        except httpx.HTTPError as e:
            detail, status = f"ERROR: {e!r}", "FAIL"
        results.append(status)
        print(f"{status}  {name}: {detail}")

    ran = [s for s in results if s != "SKIP"]
    print(f"\n{ran.count('PASS')}/{len(ran)} passed" + (f" ({results.count('SKIP')} skipped)" if "SKIP" in results else ""))
    return 0 if "FAIL" not in results else 1


if __name__ == "__main__":
    sys.exit(main())
