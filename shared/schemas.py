"""Wire format shared by every stage of the pipeline (and mirrored by the ESP32 firmware)."""

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class SignedChunk:
    sensor_id: str
    timestamp: int                   # Unix epoch milliseconds, set by the sensor
    counter: int                     # Monotonic per-sensor nonce, persisted in ESP32 NVS; receivers reject counter <= last seen
    data: dict[str, Any] = field(default_factory=dict)
    sensor_signature: str = ""       # Hex HMAC-SHA256 over signing_bytes(), set by the sensor
    gateway_signature: Optional[str] = None  # Added later by the gateway

    def signing_bytes(self) -> bytes:
        """Canonical bytes the sensor signs: every field except the signatures.

        Compact JSON with sorted keys. The ESP32 firmware must produce these
        exact bytes, so keep `data` values as ints/strings where possible
        (e.g. temperature in centi-degrees): C++ and Python format floats
        differently, and a single differing digit breaks the HMAC.
        """
        body = {
            "sensor_id": self.sensor_id,
            "timestamp": self.timestamp,
            "counter": self.counter,
            "data": self.data,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def gateway_signing_bytes(self) -> bytes:
        """Canonical bytes the gateway signs: every field except gateway_signature.

        This includes sensor_signature, so the gateway's signature vouches for
        the exact chunk it verified.
        """
        body = asdict(self)
        del body["gateway_signature"]
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, raw: str) -> "SignedChunk":
        return cls(**json.loads(raw))
