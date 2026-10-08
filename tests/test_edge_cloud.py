import uuid

import pytest
from fastapi.testclient import TestClient

from cloud import cloud_service
from edge import edge_service
from shared.processing import assess_comfort, dew_point_c, heat_index_c

edge = TestClient(edge_service.app)
cloud = TestClient(cloud_service.app)

READING = {"temp_centi_c": 2410, "humidity_centi_pct": 5500}


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(cloud_service, "DB_PATH", tmp_path / "raw_chunks.db")


def payload(**overrides):
    p = {"chunk_id": str(uuid.uuid4()), "sensor_id": "esp32-001", "timestamp": 1790000000000,
         "counter": 1, "data": dict(READING)}
    p.update(overrides)
    return p


# --- the computation ---------------------------------------------------------

def test_heat_index_matches_nws_table():
    # NWS heat-index chart: 86 F (30 C) at 70% RH feels like 95 F (35 C).
    assert heat_index_c(30.0, 70.0) == pytest.approx(35.0, abs=0.6)


def test_heat_index_mild_conditions_close_to_air_temp():
    assert heat_index_c(20.0, 50.0) == pytest.approx(19.6, abs=0.5)


def test_dew_point():
    assert dew_point_c(20.0, 50.0) == pytest.approx(9.3, abs=0.2)


def test_comfort_levels():
    assert assess_comfort({"temp_centi_c": 2200, "humidity_centi_pct": 4000})["comfort"] == "comfortable"
    assert assess_comfort({"temp_centi_c": 3000, "humidity_centi_pct": 7000})["comfort"] == "extreme_caution"
    assert assess_comfort({"temp_centi_c": 3800, "humidity_centi_pct": 8000})["comfort"] == "extreme_danger"


def test_zero_humidity_does_not_crash():
    assess_comfort({"temp_centi_c": 2000, "humidity_centi_pct": 0})


# --- edge and cloud endpoints -----------------------------------------------

@pytest.mark.parametrize("client", [edge, cloud], ids=["edge", "cloud"])
def test_process_returns_chunk_id_and_result(client):
    p = payload()
    r = client.post("/process", json=p)
    assert r.status_code == 200
    assert r.json() == {"chunk_id": p["chunk_id"], "result": assess_comfort(READING)}


def test_edge_and_cloud_agree_on_same_chunk():
    p = payload()
    assert edge.post("/process", json=p).json() == cloud.post("/process", json=p).json()


@pytest.mark.parametrize("client", [edge, cloud], ids=["edge", "cloud"])
def test_minimal_payload_accepted(client):
    r = client.post("/process", json={"chunk_id": str(uuid.uuid4()), "data": READING})
    assert r.status_code == 200


@pytest.mark.parametrize("client", [edge, cloud], ids=["edge", "cloud"])
@pytest.mark.parametrize("bad", [
    {"chunk_id": "not-a-uuid"},
    {"data": {"temp_centi_c": 2410}},                               # humidity missing
    {"data": {"temp_centi_c": 24.1, "humidity_centi_pct": 5500}},   # float
    {"data": {"temp_centi_c": 2410, "humidity_centi_pct": 20000}},  # 200 %
])
def test_malformed_rejected(client, bad):
    r = client.post("/process", json=payload(**bad))
    assert r.status_code == 422 and r.json()["reason"] == "malformed_chunk"


# --- cloud backup store -----------------------------------------------------

def test_cloud_stores_raw_chunk_and_retrieves_it():
    p = payload()
    cloud.post("/process", json=p)
    r = cloud.get(f"/retrieve/{p['chunk_id']}")
    assert r.status_code == 200
    stored = r.json()
    assert stored["data"] == READING  # the raw reading, not the processed result
    assert stored["sensor_id"] == "esp32-001" and stored["counter"] == 1
    assert stored["timestamp"] == 1790000000000


def test_cloud_stores_before_processing(monkeypatch):
    def boom(data):
        raise RuntimeError("processing crashed")

    monkeypatch.setattr(cloud_service, "assess_comfort", boom)
    p = payload()
    with pytest.raises(RuntimeError):
        cloud.post("/process", json=p)
    assert cloud.get(f"/retrieve/{p['chunk_id']}").status_code == 200


def test_cloud_rejects_duplicate_chunk_id():
    p = payload()
    assert cloud.post("/process", json=p).status_code == 200
    r = cloud.post("/process", json=p)
    assert r.status_code == 409 and r.json()["reason"] == "duplicate_chunk_id"


def test_retrieve_unknown_chunk_is_404():
    assert cloud.get(f"/retrieve/{uuid.uuid4()}").status_code == 404


# --- signed backups, final storage rules, quarantine -------------------------

def test_cloud_keeps_device_signature_with_backup():
    p = payload(sensor_signature="ab" * 64)
    cloud.post("/process", json=p)
    assert cloud.get(f"/retrieve/{p['chunk_id']}").json()["sensor_signature"] == "ab" * 64


def test_final_result_only_for_known_chunks():
    r = cloud.post("/forward", json={"chunk_id": str(uuid.uuid4()), "result": {"temp_c": 1}})
    assert r.status_code == 404 and r.json()["reason"] == "unknown_chunk_id"


def test_quarantine_withdraws_and_blocks_results():
    p = payload()
    cloud.post("/process", json=p)
    assert cloud.post("/forward", json={"chunk_id": p["chunk_id"], "result": {"temp_c": 24.1}}).status_code == 200
    cloud.post("/quarantine", json={"chunk_id": p["chunk_id"], "reason": "backup failed verification"})
    row = cloud.get("/results/recent").json()[0]
    assert row["result"] is None and row["quarantined"] == "backup failed verification"
    r = cloud.post("/forward", json={"chunk_id": p["chunk_id"], "result": {"temp_c": 24.1}})
    assert r.status_code == 409 and r.json()["reason"] == "chunk_quarantined"
    assert cloud.get("/quarantine").json()[0]["chunk_id"] == p["chunk_id"]


def test_recovered_flag_is_stored():
    p = payload()
    cloud.post("/process", json=p)
    cloud.post("/forward", json={"chunk_id": p["chunk_id"], "result": {"temp_c": 24.1}, "recovered": True})
    assert cloud.get("/results/recent").json()[0]["recovered"] is True


def test_old_database_is_migrated(tmp_path, monkeypatch):
    import sqlite3
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)          # schema from before signatures/recovery existed
    db.execute("CREATE TABLE raw_chunks (chunk_id TEXT PRIMARY KEY, received_at REAL NOT NULL, sensor_id TEXT, "
               "timestamp INTEGER, counter INTEGER, data TEXT NOT NULL)")
    db.execute("CREATE TABLE final_results (chunk_id TEXT PRIMARY KEY, stored_at REAL NOT NULL, result TEXT NOT NULL)")
    db.commit(); db.close()
    monkeypatch.setattr(cloud_service, "DB_PATH", path)
    p = payload(sensor_signature="cd" * 64)
    assert cloud.post("/process", json=p).status_code == 200
    assert cloud.get(f"/retrieve/{p['chunk_id']}").json()["sensor_signature"] == "cd" * 64
