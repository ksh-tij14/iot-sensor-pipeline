import time
import uuid

import pytest
from fastapi.testclient import TestClient

from cloud import cloud_service
from dashboard import dashboard_service
from shared.events import count_events, read_events, record_event

ACTION = {"X-Dashboard-Action": "1"}


@pytest.fixture
def event_db(tmp_path, monkeypatch):
    path = str(tmp_path / "events.db")
    monkeypatch.setattr(dashboard_service, "EVENT_DB_PATH", path)
    return path


# --- event store ---------------------------------------------------------------

def test_record_and_read_events(event_db):
    record_event("gateway", "accepted", "sensor-gateway", {"sensor_id": "esp32-001", "counter": 5}, path=event_db)
    record_event("gateway", "tamper", "sensor-gateway", {"reason": "bad_sensor_signature"}, path=event_db)
    events = read_events(event_db, limit=10)
    assert [e["event"] for e in events] == ["tamper", "accepted"]   # newest first
    assert events[1]["counter"] == 5 and events[0]["reason"] == "bad_sensor_signature"
    assert read_events(event_db, events=["accepted"])[0]["sensor_id"] == "esp32-001"
    assert count_events(event_db)["by_event"] == {"accepted": 1, "tamper": 1}


def test_recording_without_a_path_is_a_no_op(tmp_path):
    record_event("gateway", "accepted", "sensor-gateway", {}, path=None)  # must not raise


def test_reading_a_missing_store_returns_nothing(tmp_path):
    assert read_events(str(tmp_path / "none.db")) == []


# --- cloud results endpoint ---------------------------------------------------

def test_cloud_recent_results_join_raw_and_final(tmp_path, monkeypatch):
    monkeypatch.setattr(cloud_service, "DB_PATH", tmp_path / "raw.db")
    client = TestClient(cloud_service.app)
    cid = str(uuid.uuid4())
    client.post("/process", json={"chunk_id": cid, "sensor_id": "esp32-001", "timestamp": 1, "counter": 1,
                                  "data": {"temp_centi_c": 2500, "humidity_centi_pct": 6000}})
    rows = client.get("/results/recent", params={"sensor_id": "esp32-001"}).json()
    assert rows[0]["chunk_id"] == cid and rows[0]["result"] is None       # not validated yet
    client.post("/forward", json={"chunk_id": cid, "result": {"temp_c": 25.0}})
    assert client.get("/results/recent").json()[0]["result"] == {"temp_c": 25.0}
    assert client.get("/results/recent", params={"sensor_id": "other"}).json() == []


# --- dashboard API --------------------------------------------------------------

def test_overview_counts_and_device_status(event_db, monkeypatch):
    async def fake_results(limit, sensor_id):
        return [{"chunk_id": "c1", "sensor_id": sensor_id, "data": {"temp_centi_c": 3020, "humidity_centi_pct": 5900},
                 "result": {"comfort": "caution"}}]
    monkeypatch.setattr(dashboard_service, "fetch_results", fake_results)
    record_event("gateway", "accepted", "sensor-gateway", {"sensor_id": "esp32-001"}, path=event_db)
    record_event("validation", "validated", "edge-cloud-validation", {"sensor_id": "esp32-001"}, path=event_db)
    record_event("fork", "tamper", "gateway-fork", {"reason": "gateway-tampered-after-verification"}, path=event_db)

    o = TestClient(dashboard_service.app).get("/api/overview").json()
    assert o["device"]["online"] is True
    assert o["device"]["latest"]["chunk_id"] == "c1"
    assert o["counts"]["accepted"] == 1 and o["counts"]["validated"] == 1 and o["counts"]["tamper"] == 1
    assert o["tamper_by_hop"] == {"gateway-fork": 1}


def test_overview_when_cloud_is_down(event_db, monkeypatch):
    async def down(limit, sensor_id):
        return None
    monkeypatch.setattr(dashboard_service, "fetch_results", down)
    o = TestClient(dashboard_service.app).get("/api/overview").json()
    assert o["cloud_reachable"] is False and o["device"]["online"] is False


def test_events_filter_and_bad_kind(event_db):
    record_event("gateway", "accepted", "sensor-gateway", {}, path=event_db)
    record_event("gateway", "tamper", "sensor-gateway", {"reason": "x"}, path=event_db)
    client = TestClient(dashboard_service.app)
    assert [e["event"] for e in client.get("/api/events", params={"kind": "tamper"}).json()] == ["tamper"]
    assert client.get("/api/events", params={"kind": "nope"}).status_code == 400


def test_run_attack_records_result(monkeypatch):
    monkeypatch.setitem(dashboard_service.ATTACKS, "replay", ("Replay attack", lambda: "rejected: 409"))
    client = TestClient(dashboard_service.app)
    r = client.post("/api/attacks/replay", headers=ACTION).json()
    assert r["passed"] is True and r["detail"] == "rejected: 409"
    assert client.get("/api/attacks").json()["history"][0]["key"] == "replay"
    assert client.post("/api/attacks/unknown", headers=ACTION).status_code == 404


def test_failed_attack_is_reported_not_raised(monkeypatch):
    def not_caught():
        raise AssertionError("expected 409, got 200")
    monkeypatch.setitem(dashboard_service.ATTACKS, "delay", ("Packet delay", not_caught))
    r = TestClient(dashboard_service.app).post("/api/attacks/delay", headers=ACTION).json()
    assert r["passed"] is False and "NOT CAUGHT" in r["detail"]


def test_index_page_served():
    r = TestClient(dashboard_service.app).get("/")
    assert r.status_code == 200 and "Sensor Shield" in r.text


def test_actions_need_the_custom_header(monkeypatch):
    # A plain cross-site POST (no custom header) must not trigger anything.
    ran = []
    monkeypatch.setitem(dashboard_service.ATTACKS, "replay", ("Replay attack", lambda: ran.append(1) or "ok"))
    client = TestClient(dashboard_service.app)
    assert client.post("/api/attacks/replay").status_code == 403
    assert client.post("/api/attacks").status_code == 403
    assert ran == []


def test_device_counts_exclude_other_sensors(event_db, monkeypatch):
    async def none(limit, sensor_id):
        return []
    monkeypatch.setattr(dashboard_service, "fetch_results", none)
    for sid in ["esp32-001", "esp32-003", "esp32-003"]:      # one real reading, two from the attack simulator
        record_event("gateway", "accepted", "sensor-gateway", {"sensor_id": sid}, path=event_db)
        record_event("validation", "validated", "edge-cloud-validation", {"sensor_id": sid}, path=event_db)
    o = TestClient(dashboard_service.app).get("/api/overview").json()
    assert o["counts"]["accepted"] == 1 and o["counts"]["validated"] == 1


def test_device_seen_even_after_many_other_events(event_db, monkeypatch):
    async def none(limit, sensor_id):
        return []
    monkeypatch.setattr(dashboard_service, "fetch_results", none)
    record_event("gateway", "accepted", "sensor-gateway", {"sensor_id": "esp32-001"}, path=event_db)
    for _ in range(120):                                     # a burst of attack-simulator traffic
        record_event("gateway", "accepted", "sensor-gateway", {"sensor_id": "esp32-003"}, path=event_db)
    assert TestClient(dashboard_service.app).get("/api/overview").json()["device"]["online"] is True


def test_devices_list_and_selection(event_db, monkeypatch):
    seen = []
    async def results(limit, sensor_id):
        seen.append(sensor_id)
        return []
    monkeypatch.setattr(dashboard_service, "fetch_results", results)
    record_event("gateway", "accepted", "sensor-gateway", {"sensor_id": "esp32-002"}, path=event_db)
    client = TestClient(dashboard_service.app)
    devices = {d["sensor_id"]: d for d in client.get("/api/devices").json()["devices"]}
    assert devices["esp32-001"]["kind"] == "physical" and devices["esp32-001"]["online"] is False
    assert devices["esp32-002"]["kind"] == "virtual" and devices["esp32-002"]["online"] is True
    assert "esp32-003" not in devices                        # attack-simulator identity never listed
    o = client.get("/api/overview", params={"device": "esp32-002"}).json()
    assert o["device"]["sensor_id"] == "esp32-002" and o["device"]["online"] is True
    client.get("/api/readings", params={"device": "esp32-002"})
    assert seen == ["esp32-002", "esp32-002"]
    assert client.get("/api/overview", params={"device": "esp32-003"}).status_code == 400


def test_page_needs_no_internet():
    # Fonts and Chart.js are served locally: on a slow hotspot a CDN stalled the page for 30 s+.
    client = TestClient(dashboard_service.app)
    page = client.get("/").text
    assert "https://" not in page
    for asset in ["/static/vendor/chart.umd.js", "/static/vendor/fonts.css",
                  "/static/vendor/plus-jakarta-sans-latin.woff2", "/static/vendor/material-symbols-outlined.woff2"]:
        assert client.get(asset).status_code == 200, asset
