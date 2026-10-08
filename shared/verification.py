"""Device-signature check shared by gateway, fork and validation."""

from typing import Optional

from shared.crypto_utils import ecdsa_verify
from shared.schemas import SignedChunk


def check_sensor_signature(chunk: SignedChunk, keystore: dict) -> Optional[str]:
    """None if the chunk carries a valid signature from a known, non-revoked
    device; otherwise the rejection reason."""
    entry = keystore.get(chunk.sensor_id)
    if entry is None:
        return "unknown_sensor"
    if entry["revoked"]:
        return "revoked_sensor"
    if not ecdsa_verify(entry["public_key"], chunk.signing_bytes(), chunk.sensor_signature or ""):
        return "bad_sensor_signature"
    return None
