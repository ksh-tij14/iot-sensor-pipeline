import sqlite3

from shared.events import read_events, record_event, verify_chain

KEY = b"test-key"


def fill(path, n=5):
    for i in range(n):
        record_event("gateway", "accepted", "sensor-gateway", {"sensor_id": "esp32-001", "counter": i}, path=path, key=KEY)


def test_intact_chain_verifies(tmp_path):
    path = str(tmp_path / "e.db")
    fill(path)
    r = verify_chain(path, key=KEY)
    assert r["ok"] and r["checked"] == 5


def test_edited_entry_is_detected(tmp_path):
    path = str(tmp_path / "e.db")
    fill(path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE events SET reason = 'nothing to see' WHERE id = 3")
    r = verify_chain(path, key=KEY)
    assert not r["ok"] and r["first_bad_id"] == 3 and "edited" in r["reason"]


def test_deleted_entry_is_detected(tmp_path):
    path = str(tmp_path / "e.db")
    fill(path)
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM events WHERE id = 3")
    r = verify_chain(path, key=KEY)
    assert not r["ok"] and r["first_bad_id"] == 4 and "deleted" in r["reason"]


def test_rehashing_without_the_key_is_detected(tmp_path):
    # An attacker who edits an entry and recomputes the hash with a guessed key
    # still fails verification.
    path = str(tmp_path / "e.db")
    fill(path, 2)
    record_event("gateway", "tamper", "sensor-gateway", {"reason": "forged"}, path=path, key=b"wrong-key")
    assert not verify_chain(path, key=KEY)["ok"]


def test_pruned_history_still_verifies(tmp_path):
    path = str(tmp_path / "e.db")
    fill(path, 6)
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM events WHERE id <= 2")       # oldest entries pruned
    assert verify_chain(path, key=KEY)["ok"]


def test_concurrent_writers_keep_one_chain(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    path = str(tmp_path / "e.db")
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: record_event("svc", "processed", "fork-edge", {"counter": i}, path=path, key=KEY),
                      range(40)))
    r = verify_chain(path, key=KEY)
    assert r["ok"] and r["checked"] == 40
    assert len(read_events(path, limit=100)) == 40
