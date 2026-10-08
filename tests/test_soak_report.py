import sqlite3

from shared.events import record_event
from tests.soak_report import soak_report


def _set_time(path, times):
    with sqlite3.connect(path) as db:
        for i, t in enumerate(times, start=1):
            db.execute("UPDATE events SET time = ? WHERE id = ?", (t, i))


def test_soak_report_counts_gaps_and_skipped_counters(tmp_path):
    path = str(tmp_path / "events.db")
    counters = [10, 11, 12, 15, 16]                 # 13 and 14 consumed by failed sends
    times = [1000, 1005, 1010, 1030, 1035]          # one 20 s gap
    for c in counters:
        record_event("gateway", "accepted", "sensor-gateway", {"sensor_id": "esp32-001", "counter": c}, path=path)
    _set_time(path, times)
    r = soak_report(path, "esp32-001", hours=1, now=1040)
    assert r["accepted"] == 5 and r["expected"] == 8
    assert r["gaps_over_10s"] == 1 and r["longest_gap_s"] == 20
    assert r["counter_values_skipped"] == 2 and r["counter_monotonic"] is True


def test_soak_report_with_no_readings(tmp_path):
    assert soak_report(str(tmp_path / "none.db"), "esp32-001", hours=1)["accepted"] == 0
