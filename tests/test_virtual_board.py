from shared.config import load_keystore, load_sensor_private_keys
from shared.schemas import SignedChunk
from shared.verification import check_sensor_signature
from tests import virtual_board


def test_virtual_board_chunks_verify_like_the_firmware():
    body = virtual_board.make_body("esp32-002", load_sensor_private_keys()["esp32-002"], 3_000_000_123)
    chunk = SignedChunk(**body)
    assert check_sensor_signature(chunk, load_keystore()) is None
    assert set(body["data"]) == {"humidity_centi_pct", "temp_centi_c"}
    assert all(isinstance(v, int) for v in body["data"].values())


def test_counter_is_persisted_before_use(tmp_path):
    path = tmp_path / "counter"
    c = virtual_board.Counter(path)
    first = c.next()
    assert first == virtual_board.COUNTER_FLOOR + 1 and path.read_text() == str(first)
    assert virtual_board.Counter(path).next() == first + 1    # a restart never reuses a value
