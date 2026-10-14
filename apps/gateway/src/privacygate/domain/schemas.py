"""Gateway DTOs mirroring packages/shared JSON schemas (Pydantic v2, strict)."""
from __future__ import annotations

import base64
import binascii
import math
import re
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

strict = ConfigDict(extra="forbid")

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
RES_RE = re.compile(r"^0x[0-9a-f]{64}$")
WALLET_LOWER_RE = re.compile(r"^0x[0-9a-f]{40}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
SIG_B64_RE = re.compile(r"^[A-Za-z0-9+/]{86}==$")

INSIGHT_FIELDS = ("event_id", "event_type", "severity", "observed_at", "model_version")


def _b64_len(value: str, nbytes: int) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"invalid base64: {e}") from e
    if len(raw) != nbytes:
        raise ValueError(f"expected {nbytes} bytes, got {len(raw)}")
    return value


class SensorTelemetryV1(BaseModel):
    model_config = strict
    temp_c: float = Field(ge=-40, le=200)
    vibration_mm_s: float = Field(ge=0, le=100)
    rpm: int = Field(ge=0, le=30000)

    @field_validator("temp_c", "vibration_mm_s")
    @classmethod
    def _finite(cls, v: float) -> float:
        if not math.isfinite(v):
            raise ValueError("must be finite")
        return v


class SignedTelemetryV1(BaseModel):
    model_config = strict
    schema_version: Literal[1]
    device_id: uuid.UUID
    resource_id: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    sequence: int = Field(gt=0)
    issued_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
    telemetry: SensorTelemetryV1
    signature_b64: str = Field(pattern=r"^[A-Za-z0-9+/]{86}==$")

    @field_validator("signature_b64")
    @classmethod
    def _sig_len(cls, v: str) -> str:
        return _b64_len(v, 64)


class InsightV1(BaseModel):
    """Only subscriber-decryptable payload. Exactly 5 fields."""

    model_config = strict
    event_id: uuid.UUID
    event_type: Literal["MACHINE_ANOMALY"]
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    observed_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
    model_version: str = Field(min_length=1, max_length=64)


class PolicyManifestV1(BaseModel):
    model_config = strict
    resource_id: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    recipient_wallet_lowercase: str = Field(pattern=r"^0x[0-9a-f]{40}$")
    scope: Literal["READ_INSIGHT"]
    allowed_event_types: list[Literal["MACHINE_ANOMALY"]] = Field(min_length=1, max_length=1)
    allowed_fields: list[str] = Field(min_length=5, max_length=5)
    expires_at_unix: int = Field(gt=0)
    policy_revision: int = Field(gt=0)

    @field_validator("allowed_fields")
    @classmethod
    def _exact_fields(cls, v: list[str]) -> list[str]:
        if sorted(v) != sorted(INSIGHT_FIELDS):
            raise ValueError(f"allowed_fields must be exactly {sorted(INSIGHT_FIELDS)}")
        return v


class DeviceEnrollRequest(BaseModel):
    """PG-010 owner device enrollment. No private key ever accepted."""

    model_config = strict
    resource_id: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    device_id: uuid.UUID
    name: str = Field(min_length=1, max_length=128)
    ed25519_public_key_b64: str

    @field_validator("ed25519_public_key_b64")
    @classmethod
    def _pubkey_len(cls, v: str) -> str:
        return _b64_len(v, 32)
