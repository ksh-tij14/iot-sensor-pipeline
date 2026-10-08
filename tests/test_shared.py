from shared.config import load_keystore, load_sensor_private_keys
from shared.crypto_utils import (ecdsa_sign, ecdsa_verify, generate_keypair, public_key_from_private,
                                 sign, verify)
from shared.schemas import SignedChunk
from shared.verification import check_sensor_signature

KEYSTORE = load_keystore()
PRIVATE = load_sensor_private_keys()["esp32-001"]
PUBLIC = KEYSTORE["esp32-001"]["public_key"]


def make_chunk() -> SignedChunk:
    chunk = SignedChunk(sensor_id="esp32-001", timestamp=1700000000000, counter=1,
                        data={"temp_centi_c": 2150, "humidity_centi_pct": 4000})
    chunk.sensor_signature = ecdsa_sign(PRIVATE, chunk.signing_bytes())
    return chunk


def test_signing_bytes_are_canonical():
    # The firmware must emit exactly these bytes; this test is the contract.
    assert make_chunk().signing_bytes() == (
        b'{"counter":1,"data":{"humidity_centi_pct":4000,"temp_centi_c":2150},'
        b'"sensor_id":"esp32-001","timestamp":1700000000000}'
    )


def test_valid_signature_verifies():
    chunk = make_chunk()
    assert len(chunk.sensor_signature) == 128           # raw r||s, as the firmware sends it
    assert ecdsa_verify(PUBLIC, chunk.signing_bytes(), chunk.sensor_signature)


def test_tampered_data_fails():
    chunk = make_chunk()
    chunk.data["temp_centi_c"] = 9900
    assert not ecdsa_verify(PUBLIC, chunk.signing_bytes(), chunk.sensor_signature)


def test_counter_is_covered_by_signature():
    chunk = make_chunk()
    chunk.counter = 2  # an attacker can't bump the counter without re-signing
    assert not ecdsa_verify(PUBLIC, chunk.signing_bytes(), chunk.sensor_signature)


def test_wrong_key_fails():
    chunk = make_chunk()
    assert not ecdsa_verify(KEYSTORE["esp32-002"]["public_key"], chunk.signing_bytes(), chunk.sensor_signature)


def test_malformed_signatures_are_rejected_not_raised():
    data = make_chunk().signing_bytes()
    for bad in ["", "zz" * 64, "00" * 64, "ab" * 32, "ab" * 65]:
        assert not ecdsa_verify(PUBLIC, data, bad)
    assert not ecdsa_verify("04deadbeef", data, make_chunk().sensor_signature)   # bad public key


def test_keypair_round_trip():
    private, public = generate_keypair()
    assert public_key_from_private(private) == public and len(public) == 130
    assert ecdsa_verify(public, b"x", ecdsa_sign(private, b"x"))


def test_servers_hold_only_public_keys():
    # The keystore the gateway loads must not contain anything that can sign.
    for entry in KEYSTORE.values():
        assert set(entry) == {"public_key", "revoked"} and entry["public_key"].startswith("04")


def test_check_sensor_signature_reasons():
    chunk = make_chunk()
    assert check_sensor_signature(chunk, KEYSTORE) is None
    revoked = {**KEYSTORE, "esp32-001": {**KEYSTORE["esp32-001"], "revoked": True}}
    assert check_sensor_signature(chunk, revoked) == "revoked_sensor"
    chunk.sensor_id = "esp32-999"
    assert check_sensor_signature(chunk, KEYSTORE) == "unknown_sensor"


def test_hmac_still_used_for_gateway_signature():
    assert verify(b"k", b"data", sign(b"k", b"data"))
    assert not verify(b"k", b"data", sign(b"other", b"data"))


def test_json_round_trip_keeps_signature_valid():
    chunk = SignedChunk.from_json(make_chunk().to_json())
    assert ecdsa_verify(PUBLIC, chunk.signing_bytes(), chunk.sensor_signature)
