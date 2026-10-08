import time

import httpx
import pytest
from fastapi.testclient import TestClient

from gateway import gateway_service
from shared.config import GATEWAY_SECRET, load_keystore, load_sensor_private_keys
from shared.crypto_utils import ecdsa_sign, verify
from shared.schemas import SignedChunk
from shared.service_utils import RateLimiter

PRIVATE = load_sensor_private_keys()["esp32-001"]


@pytest.fixture
def forwarded(monkeypatch):
    """Capture forwarded chunks instead of calling the real fork point."""
    sent = []

    async def fake_forward(chunk):
        sent.append(chunk)

    monkeypatch.setattr(gateway_service, "forward", fake_forward)
    gateway_service.counters.clear()
    return sent


client = TestClient(gateway_service.app)


def now_ms() -> int:
    return int(time.time() * 1000)


def body(counter=1, age_seconds=0, **overrides):
    chunk = SignedChunk(sensor_id="esp32-001", timestamp=now_ms() - int(age_seconds * 1000), counter=counter,
                        data={"humidity_centi_pct": 5500, "temp_centi_c": 2410})
    chunk.sensor_signature = ecdsa_sign(PRIVATE, chunk.signing_bytes())
    b = {k: v for k, v in chunk.__dict__.items() if k != "gateway_signature"}
    b.update(overrides)
    return b


def test_valid_chunk_is_countersigned_and_forwarded(forwarded):
    sent_body = body()
    r = client.post("/ingest", json=sent_body)
    assert r.status_code == 200
    [chunk] = forwarded
    assert chunk.sensor_signature == sent_body["sensor_signature"]  # untouched
    assert verify(GATEWAY_SECRET, chunk.gateway_signing_bytes(), chunk.gateway_signature)


def test_exact_firmware_body_is_accepted(forwarded):
    # Byte-for-byte what firmware/src/main.cpp builds and signs.
    ts = now_ms()
    signing = ('{"counter":7,"data":{"humidity_centi_pct":5500,"temp_centi_c":2410},'
               f'"sensor_id":"esp32-001","timestamp":{ts}}}')
    sig = ecdsa_sign(PRIVATE, signing.encode())
    raw = (f'{{"sensor_id":"esp32-001","timestamp":{ts},"counter":7,'
           '"data":{"humidity_centi_pct":5500,"temp_centi_c":2410},'
           f'"sensor_signature":"{sig}"}}')
    r = client.post("/ingest", content=raw, headers={"Content-Type": "application/json"})
    assert r.status_code == 200


def test_tampered_data_rejected(forwarded):
    b = body()
    b["data"]["temp_centi_c"] = 9999
    r = client.post("/ingest", json=b)
    assert r.status_code == 401 and r.json()["reason"] == "bad_sensor_signature"
    assert forwarded == []


def test_unknown_sensor_rejected(forwarded):
    r = client.post("/ingest", json=body(sensor_id="esp32-999"))
    assert r.status_code == 401 and r.json()["reason"] == "unknown_sensor"
    assert forwarded == []


def test_revoked_sensor_rejected(forwarded, monkeypatch):
    keystore = load_keystore()
    revoked = {**keystore, "esp32-001": {**keystore["esp32-001"], "revoked": True}}
    monkeypatch.setattr(gateway_service, "load_keystore", lambda: revoked)
    r = client.post("/ingest", json=body())
    assert r.status_code == 403 and r.json()["reason"] == "revoked_sensor"
    assert forwarded == []


@pytest.mark.parametrize("age", [600, -600])            # 10 minutes old, or 10 minutes in the future
def test_stale_timestamp_rejected_without_using_the_counter(forwarded, age):
    r = client.post("/ingest", json=body(counter=5, age_seconds=age))
    assert r.status_code == 409 and r.json()["reason"] == "stale_timestamp"
    assert client.post("/ingest", json=body(counter=5)).status_code == 200   # counter 5 still free


def test_small_clock_skew_accepted(forwarded):
    assert client.post("/ingest", json=body(age_seconds=20)).status_code == 200


def test_replay_and_old_counter_rejected(forwarded):
    assert client.post("/ingest", json=body(counter=5)).status_code == 200
    assert client.post("/ingest", json=body(counter=5)).status_code == 409  # replay
    assert client.post("/ingest", json=body(counter=3)).status_code == 409  # delayed/old
    assert client.post("/ingest", json=body(counter=9)).status_code == 200  # gaps are fine
    assert [c.counter for c in forwarded] == [5, 9]


def test_bad_signature_does_not_advance_counter(forwarded):
    client.post("/ingest", json=body(counter=100, sensor_signature="0" * 128))
    assert client.post("/ingest", json=body(counter=2)).status_code == 200


@pytest.mark.parametrize("bad", [
    {"counter": "1"},                             # string, not int
    {"counter": -1},
    {"data": {"temp_centi_c": 24.1}},             # floats not allowed
    {"sensor_signature": "not-hex"},
    {"sensor_signature": "ab" * 32},              # HMAC-sized: no longer accepted
    {"gateway_signature": "a" * 64},              # sensors can't send this
    {"sensor_id": 'esp32-001"'},
])
def test_malformed_rejected(forwarded, bad):
    r = client.post("/ingest", json=body(**bad))
    assert r.status_code == 422 and r.json()["reason"] == "malformed_chunk"
    assert forwarded == []


def test_missing_field_and_non_json_rejected(forwarded):
    b = body()
    del b["counter"]
    assert client.post("/ingest", json=b).status_code == 422
    r = client.post("/ingest", content="not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 422
    assert forwarded == []


def test_fork_down_returns_502(monkeypatch):
    async def failing_forward(chunk):
        raise httpx.ConnectError("fork down")

    monkeypatch.setattr(gateway_service, "forward", failing_forward)
    gateway_service.counters.clear()
    assert client.post("/ingest", json=body()).status_code == 502


def test_rate_limit_on_the_direct_port(forwarded, monkeypatch):
    # TestClient talks to "testserver:80"; treat that as the directly exposed port.
    monkeypatch.setattr(gateway_service, "TLS_PORT", 80)
    monkeypatch.setattr(gateway_service, "limiter", RateLimiter(rate=0.001, burst=3))
    codes = [client.post("/ingest", json=body(counter=i)).status_code for i in range(1, 6)]
    assert codes == [200, 200, 200, 429, 429]


def test_rate_limiter_refills():
    limiter = RateLimiter(rate=1000, burst=1)
    assert limiter.allow("a") and limiter.allow("b")       # separate buckets per client
    time.sleep(0.01)
    assert limiter.allow("a")
