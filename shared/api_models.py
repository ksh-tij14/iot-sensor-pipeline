"""Request models for the HTTP services: strict validation of incoming chunks.

Strict types, because signatures are recomputed from these values: coercing
"5" to 5, or accepting floats (whose formatting differs between C++ and
Python), would change the signed bytes.
"""

from typing import Annotated, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from shared.schemas import SignedChunk

HexSignature = Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]          # HMAC-SHA256
EcdsaSignature = Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{128}$")]       # ECDSA P-256, raw r||s


class SensorChunkIn(BaseModel):
    """What a sensor sends to the gateway."""

    model_config = ConfigDict(extra="forbid")  # a sensor never sends gateway_signature

    sensor_id: Annotated[StrictStr, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
    timestamp: Annotated[StrictInt, Field(ge=0)]
    counter: Annotated[StrictInt, Field(ge=1, le=2**32 - 1)]  # firmware uses uint32
    data: Annotated[dict[str, StrictInt | StrictStr], Field(max_length=32)]
    sensor_signature: EcdsaSignature

    def to_chunk(self) -> SignedChunk:
        return SignedChunk(**self.model_dump())


class GatewayChunkIn(SensorChunkIn):
    """What travels after the gateway: the same chunk plus gateway_signature."""

    gateway_signature: HexSignature


class ReadingData(BaseModel):
    """The reading itself, in the firmware's integer units (hundredths)."""

    model_config = ConfigDict(extra="allow")  # future sensors may add fields

    temp_centi_c: Annotated[StrictInt, Field(ge=-4000, le=8000)]      # -40..80 C
    humidity_centi_pct: Annotated[StrictInt, Field(ge=0, le=10000)]  # 0..100 %


class ProcessIn(BaseModel):
    """What the fork sends to edge and cloud. Only chunk_id and data are
    required; the rest is kept by the cloud's backup store when present."""

    model_config = ConfigDict(extra="forbid")

    chunk_id: UUID
    data: ReadingData
    sensor_id: Optional[StrictStr] = None
    timestamp: Optional[StrictInt] = None
    counter: Optional[StrictInt] = None
    # The device's own signature, stored with the cloud backup so a backup can
    # be re-verified before it's ever used for recovery.
    sensor_signature: Optional[EcdsaSignature] = None
