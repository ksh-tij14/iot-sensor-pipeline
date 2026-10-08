from concurrent.futures import ThreadPoolExecutor

import pytest

from shared.service_utils import CounterTracker, SqliteCounterTracker


@pytest.fixture(params=["memory", "sqlite"])
def tracker(request, tmp_path):
    return CounterTracker() if request.param == "memory" else SqliteCounterTracker(str(tmp_path / "c.db"))


def test_increasing_counters_accepted_with_gaps(tracker):
    assert tracker.check_and_record("s", 1)
    assert tracker.check_and_record("s", 2)
    assert tracker.check_and_record("s", 10)
    assert tracker.last_seen("s") == 10


def test_repeated_or_older_counter_rejected(tracker):
    tracker.check_and_record("s", 5)
    assert not tracker.check_and_record("s", 5)
    assert not tracker.check_and_record("s", 3)
    assert tracker.last_seen("s") == 5


def test_sensors_are_independent(tracker):
    tracker.check_and_record("a", 100)
    assert tracker.check_and_record("b", 1)
    assert tracker.last_seen("missing") is None


def test_two_instances_on_one_file_share_counters(tmp_path):
    # Two gateway instances behind a load balancer: a chunk accepted by one
    # must count as a replay at the other.
    path = str(tmp_path / "shared.db")
    gateway_1, gateway_2 = SqliteCounterTracker(path), SqliteCounterTracker(path)
    assert gateway_1.check_and_record("s", 7)
    assert not gateway_2.check_and_record("s", 7)   # replay routed to the other instance
    assert not gateway_2.check_and_record("s", 6)   # delayed chunk
    assert gateway_2.check_and_record("s", 8)
    assert not gateway_1.check_and_record("s", 8)


def test_concurrent_duplicates_accepted_exactly_once(tmp_path):
    path = str(tmp_path / "race.db")
    trackers = [SqliteCounterTracker(path) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda t: t.check_and_record("s", 42), trackers))
    assert results.count(True) == 1


def test_counters_survive_restart(tmp_path):
    path = str(tmp_path / "persist.db")
    SqliteCounterTracker(path).check_and_record("s", 9)
    assert not SqliteCounterTracker(path).check_and_record("s", 9)  # "restarted" gateway
