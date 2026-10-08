import json
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from fork import fork_service
from shared.config import GATEWAY_SECRET, load_keystore, load_sensor_private_keys
from shared.crypto_utils import ecdsa_sign, sign
from shared.schemas import SignedChunk

PRIVATE = load_sensor_private_keys()["esp32-001"]
client = TestClient(fork_service.app)
validated = []  # bodies the fork sent to the validation service


@pytest.fixture
def sent(monkeypatch):
    """Capture what would go to cloud/edge instead of making real requests."""
    calls = []

    async def fake_send(http_client, url, payload):
        calls.append((url, payload))
        return {"chunk_id": payload["chunk_id"], "result": {"source": url}}

    async def fake_validate(body):
        validated.append(body)
        return {"status": "match"}

    validated.clear()
    monkeypatch.setattr(fork_service, "send", fake_send)
    monkeypatch.setattr(fork_service, "validate", fake_validate)
    fork_service.counters.clear()
    return calls


def envelope(counter=1, data=None):
    """A chunk as the gateway would forward it: sensor- and gateway-signed."""
    chunk = SignedChunk(sensor_id="esp32-001", timestamp=1790000000000, counter=counter,
                        data=data or {"humidity_centi_pct": 5500, "temp_centi_c": 2410})
    chunk.sensor_signature = ecdsa_sign(PRIVATE, chunk.signing_bytes())
    chunk.gateway_signature = sign(GATEWAY_SECRET, chunk.gateway_signing_bytes())
    return chunk


def test_valid_chunk_goes_to_cloud_and_edge_with_same_chunk_id(sent):
    r = client.post("/forward", json=json.loads(envelope().to_json()))
    assert r.status_code == 200
    assert len(sent) == 2
    urls = {url for url, _ in sent}
    assert urls == set(fork_service.TARGETS.values())
    (_, cloud_payload), (_, edge_payload) = sent
    assert cloud_payload == edge_payload
    assert uuid.UUID(cloud_payload["chunk_id"])  # a real UUID
    assert cloud_payload["chunk_id"] == r.json()["chunk_id"]
    assert cloud_payload["data"] == {"humidity_centi_pct": 5500, "temp_centi_c": 2410}
    assert "gateway_signature" not in cloud_payload        # only the device signature travels on, for the backup


def test_both_results_sent_to_validation(sent):
    r = client.post("/forward", json=json.loads(envelope().to_json()))
    [body] = validated
    assert body["chunk_id"] == r.json()["chunk_id"]
    assert body["sensor_id"] == "esp32-001"
    assert body["cloud_result"] == {"source": fork_service.TARGETS["cloud"]}
    assert body["edge_result"] == {"source": fork_service.TARGETS["edge"]}
    assert r.json()["validation"] == {"status": "match"}


def test_rejected_chunk_never_reaches_validation(sent):
    chunk = envelope()
    chunk.data["temp_centi_c"] = 9999
    client.post("/forward", json=json.loads(chunk.to_json()))
    assert validated == []


def test_each_chunk_gets_a_new_chunk_id(sent):
    client.post("/forward", json=json.loads(envelope(counter=1).to_json()))
    client.post("/forward", json=json.loads(envelope(counter=2).to_json()))
    assert sent[0][1]["chunk_id"] != sent[2][1]["chunk_id"]


def test_bad_gateway_signature_rejected(sent):
    chunk = envelope()
    chunk.data["temp_centi_c"] = 9999  # changed after the gateway signed
    r = client.post("/forward", json=json.loads(chunk.to_json()))
    assert r.status_code == 401 and r.json()["reason"] == "bad_gateway_signature"
    assert sent == []


def test_gateway_tampering_after_verification_detected(sent):
    # Someone with the gateway key alters the reading and re-signs as the gateway.
    # The gateway signature is valid, but the sensor's no longer matches.
    chunk = envelope()
    chunk.data["temp_centi_c"] = 9999
    chunk.gateway_signature = sign(GATEWAY_SECRET, chunk.gateway_signing_bytes())
    r = client.post("/forward", json=json.loads(chunk.to_json()))
    assert r.status_code == 401
    assert r.json()["reason"] == "gateway-tampered-after-verification"
    assert sent == []


def test_unknown_sensor_signed_by_gateway_detected(sent):
    chunk = envelope()
    chunk.sensor_id = "esp32-999"
    chunk.gateway_signature = sign(GATEWAY_SECRET, chunk.gateway_signing_bytes())
    r = client.post("/forward", json=json.loads(chunk.to_json()))
    assert r.json()["reason"] == "gateway-tampered-after-verification"
    assert sent == []


def test_replayed_chunk_rejected(sent):
    body = json.loads(envelope(counter=5).to_json())
    assert client.post("/forward", json=body).status_code == 200
    assert client.post("/forward", json=body).status_code == 409
    assert len(sent) == 2  # only the first one was forwarded


def test_missing_gateway_signature_rejected(sent):
    chunk = envelope()
    chunk.gateway_signature = None
    r = client.post("/forward", json=json.loads(chunk.to_json()))
    assert r.status_code == 422 and r.json()["reason"] == "malformed_chunk"
    assert sent == []


def test_one_target_down_returns_502(monkeypatch):
    async def half_down(http_client, url, payload):
        if "8003" in url or "edge" in url:
            raise httpx.ConnectError("edge down")
        return {"chunk_id": payload["chunk_id"], "result": {}}

    monkeypatch.setattr(fork_service, "send", half_down)
    fork_service.counters.clear()
    r = client.post("/forward", json=json.loads(envelope().to_json()))
    assert r.status_code == 502
    assert "error" not in r.json()["results"]["cloud"]
    assert "edge down" in r.json()["results"]["edge"]["error"]


def test_signature_forwarded_with_the_backup(sent):
    chunk = envelope()
    client.post("/forward", json=json.loads(chunk.to_json()))
    assert all(payload["sensor_signature"] == chunk.sensor_signature for _, payload in sent)


def test_revoked_sensor_rejected_at_fork(sent, monkeypatch):
    keystore = load_keystore()
    revoked = {**keystore, "esp32-001": {**keystore["esp32-001"], "revoked": True}}
    monkeypatch.setattr(fork_service, "load_keystore", lambda: revoked)
    r = client.post("/forward", json=json.loads(envelope().to_json()))
    assert r.status_code == 403 and r.json()["reason"] == "revoked_sensor"
    assert sent == []
