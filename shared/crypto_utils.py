"""Signing helpers.

- Sensor signatures: ECDSA P-256 over SHA-256. Asymmetric: each device holds
  its own private key; servers hold only public keys, so a compromised server
  can verify readings but can't forge them.
- Gateway signature: HMAC-SHA256 with a key shared by gateway and fork (both
  server-side).
Signatures travel as lowercase hex; ECDSA signatures as raw r||s (64 bytes),
the format the firmware produces.
"""

import hashlib
import hmac
from functools import lru_cache

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CURVE = ec.SECP256R1()


# --- HMAC (gateway signature) -------------------------------------------------

def sign(secret: bytes, payload_bytes: bytes) -> str:
    """Return the hex HMAC-SHA256 of payload_bytes under secret."""
    return hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()


def verify(secret: bytes, payload_bytes: bytes, signature: str) -> bool:
    """Check an HMAC in constant time.

    Never compare signatures with `==`: it returns as soon as a character
    differs, which leaks timing information an attacker can use to guess a
    valid signature byte by byte. hmac.compare_digest always takes the same time.
    """
    expected = sign(secret, payload_bytes)
    return hmac.compare_digest(expected.encode("ascii"), signature.encode("utf-8"))


# --- ECDSA P-256 (sensor signature) -------------------------------------------

def generate_keypair() -> tuple[str, str]:
    """(private key as 32-byte hex, public key as uncompressed-point hex)."""
    key = ec.generate_private_key(CURVE)
    return (key.private_numbers().private_value.to_bytes(32, "big").hex(),
            key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex())


@lru_cache(maxsize=64)
def _private_key(private_hex: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int(private_hex, 16), CURVE)


@lru_cache(maxsize=256)
def _public_key(public_hex: str) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, bytes.fromhex(public_hex))


def public_key_from_private(private_hex: str) -> str:
    return _private_key(private_hex).public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint).hex()


def ecdsa_sign(private_hex: str, payload_bytes: bytes) -> str:
    """Raw r||s signature (128 hex chars) over SHA-256(payload_bytes)."""
    der = _private_key(private_hex).sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def ecdsa_verify(public_hex: str, payload_bytes: bytes, signature_hex: str) -> bool:
    """True only for a valid signature; any malformed key or signature is False."""
    try:
        raw = bytes.fromhex(signature_hex)
        if len(raw) != 64:
            return False
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        _public_key(public_hex).verify(der, payload_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature):
        return False
