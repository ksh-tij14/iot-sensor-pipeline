import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from shared.config import load_sensor_private_keys
from shared.crypto_utils import ecdsa_sign
from shared.processing import assess_comfort
from shared.schemas import SignedChunk
from validation import validation_service
from validation.validation_service import check_anomalies, compare_results

client = TestClient(validation_service.app)
DATA = {"temp_centi_c": 2400, "humidity_centi_pct": 5500}
RESULT = assess_comfort(DATA)
PRIVATE = load_sensor_private_keys()["esp32-001"]


def signed_backup(chunk_id, data=None, tamper_after_signing=None):
    """A backup as the cloud stores it: the raw reading plus the device's signature."""
    chunk = SignedChunk(sensor_id="esp32-001", timestamp=1790000000000, counter=42, data=dict(data or DATA))
    chunk.sensor_signature = ecdsa_sign(PRIVATE, chunk.signing_bytes())
    backup = {"chunk_id": chunk_id, "sensor_id": chunk.sensor_id, "timestamp": chunk.timestamp,
              "counter": chunk.counter, "data": dict(chunk.data), "sensor_signature": chunk.sensor_signature}
    if tamper_after_signing:
        backup["data"].update(tamper_after_signing)
    return backup


@pytest.fixture(autouse=True)
def fake_cloud(monkeypatch):
    """Record calls to the cloud instead of making them. The backup is genuine by default."""
    calls = {"forward": [], "recovered": [], "retrieve": [], "quarantine": [], "backup": {}}

    async def fake_forward(chunk_id, result, recovered=False):
        calls["forward"].append(chunk_id)
        calls["recovered"].append(recovered)
        return {"status": "stored", "chunk_id": chunk_id}

    async def fake_retrieve(chunk_id):
        calls["retrieve"].append(chunk_id)
        return calls["backup"].get("override") or signed_backup(chunk_id)

    async def fake_quarantine(chunk_id, reason):
        calls["quarantine"].append((chunk_id, reason))

    monkeypatch.setattr(validation_service, "forward_final", fake_forward)
    monkeypatch.setattr(validation_service, "retrieve_backup", fake_retrieve)
    monkeypatch.setattr(validation_service, "quarantine", fake_quarantine)
    validation_service.history.clear()
    return calls


def post(cloud_result, edge_result, sensor_id="esp32-001"):
    return client.post("/validate", json={"chunk_id": str(uuid.uuid4()), "sensor_id": sensor_id,
                                          "cloud_result": cloud_result, "edge_result": edge_result})


def reading(temp_c, humidity_pct=55.0):
    return {"temp_c": temp_c, "humidity_pct": humidity_pct}


# --- cloud vs edge comparison -------------------------------------------------

def test_identical_results_match():
    assert compare_results(RESULT, dict(RESULT)) == {}


def test_small_difference_within_tolerance_matches():
    assert compare_results({"heat_index_c": 24.0}, {"heat_index_c": 24.3}) == {}  # 1.2%


def test_difference_beyond_tolerance_mismatches():
    diff = compare_results({"heat_index_c": 24.0}, {"heat_index_c": 25.0})  # 4%
    assert diff["heat_index_c"]["relative_difference"] == 0.04


def test_label_and_missing_field_mismatch():
    diff = compare_results({"comfort": "comfortable", "dew_point_c": 9.0}, {"comfort": "danger"})
    assert diff["comfort"]["problem"] == "values differ"
    assert diff["dew_point_c"]["problem"] == "missing on one side"


def test_match_forwards_to_cloud(fake_cloud):
    r = post(RESULT, dict(RESULT))
    body = r.json()
    assert r.status_code == 200 and body["status"] == "match"
    assert body["checks"]["cloud_edge"]["passed"] is True
    assert body["action"] == "forwarded to cloud"
    assert fake_cloud["forward"] == [body["chunk_id"]] and fake_cloud["recovered"] == [False]
    assert fake_cloud["retrieve"] == []


def test_mismatch_restores_result_from_verified_backup(fake_cloud):
    tampered = dict(RESULT, temp_c=40.0)
    body = post(RESULT, tampered).json()
    assert body["status"] == "mismatch" and body["recovered"] is True
    assert "temp_c" in body["checks"]["cloud_edge"]["differences"]
    assert fake_cloud["retrieve"] == [body["chunk_id"]]                 # backup pulled
    assert body["result"] == assess_comfort(DATA)                       # recomputed from it
    assert fake_cloud["forward"] == [body["chunk_id"]] and fake_cloud["recovered"] == [True]
    assert fake_cloud["quarantine"] == []


def test_tampered_backup_is_quarantined_not_used(fake_cloud):
    fake_cloud["backup"]["override"] = signed_backup(str(uuid.uuid4()), tamper_after_signing={"temp_centi_c": 9900})
    body = post(RESULT, dict(RESULT, temp_c=40.0)).json()
    assert body["status"] == "mismatch" and body["recovered"] is False
    assert "bad_sensor_signature" in body["reason"]
    assert fake_cloud["forward"] == []                                  # nothing stored
    assert [cid for cid, _ in fake_cloud["quarantine"]] == [body["chunk_id"]]


def test_unsigned_backup_is_quarantined(fake_cloud):
    backup = signed_backup(str(uuid.uuid4()))
    del backup["sensor_signature"]
    fake_cloud["backup"]["override"] = backup
    body = post(RESULT, dict(RESULT, temp_c=40.0)).json()
    assert body["recovered"] is False and "no device signature" in body["reason"]
    assert fake_cloud["forward"] == []


def test_mismatch_with_cloud_backup_unreachable_quarantines(fake_cloud, monkeypatch):
    async def down(chunk_id):
        raise httpx.ConnectError("cloud down")

    monkeypatch.setattr(validation_service, "retrieve_backup", down)
    body = post(RESULT, dict(RESULT, temp_c=40.0)).json()
    assert body["status"] == "mismatch" and body["recovered"] is False
    assert "backup unavailable" in body["reason"]
    assert fake_cloud["forward"] == []


def test_malformed_request_rejected():
    r = client.post("/validate", json={"chunk_id": "nope", "cloud_result": {}, "edge_result": {}})
    assert r.status_code == 422


# --- anomaly check ------------------------------------------------------------

def test_no_anomaly_check_until_enough_history():
    checks = check_anomalies("s", reading(24.0))
    assert all(not c["anomaly"] and "building history" in c["note"] for c in checks)


def test_stable_whole_number_readings_allow_one_degree_change():
    # DHT11 style: identical readings, stddev 0. Without the floor, 25 would be
    # infinitely many standard deviations away.
    for _ in range(10):
        check_anomalies("s", reading(24.0))
    [temp] = [c for c in check_anomalies("s", reading(25.0)) if c["metric"] == "temp_c"]
    assert temp["stddev"] == 0 and temp["stddev_used"] == 1.0
    assert temp["anomaly"] is False


def test_sudden_jump_is_flagged():
    for _ in range(10):
        check_anomalies("s", reading(24.0))
    [temp] = [c for c in check_anomalies("s", reading(30.0)) if c["metric"] == "temp_c"]
    assert temp["anomaly"] is True and temp["deviations"] == 6.0


def test_history_is_per_sensor():
    for _ in range(10):
        check_anomalies("kitchen", reading(30.0))
    checks = check_anomalies("bedroom", reading(20.0))
    assert all("building history" in c["note"] for c in checks)


def test_anomaly_flagged_but_chunk_still_forwarded(fake_cloud):
    for _ in range(10):
        post(reading(24.0), reading(24.0))
    body = post(reading(35.0), reading(35.0)).json()
    assert body["status"] == "match"
    assert body["checks"]["anomaly"]["flagged"] is True
    assert body["action"] == "forwarded to cloud"
    assert len(fake_cloud["forward"]) == 11


def test_mismatched_results_do_not_enter_history(fake_cloud):
    post(reading(24.0), reading(99.0))
    assert validation_service.history == {}


def test_anomaly_history_survives_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(validation_service, "STATE_DB", str(tmp_path / "state.db"))
    for _ in range(10):
        check_anomalies("s", reading(24.0))
    validation_service.history.clear()                     # as after a restart
    [temp] = [c for c in check_anomalies("s", reading(30.0)) if c["metric"] == "temp_c"]
    assert temp["anomaly"] is True                         # history was reloaded from disk
