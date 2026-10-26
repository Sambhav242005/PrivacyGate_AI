"""Strict public inputs; errors never echo input values."""

import re
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


def uuid_string(value: str) -> str:
    if str(UUID(value)) != value:
        raise ValueError("Canonical UUID required")
    return value


def resource_string(value: str) -> str:
    if not re.fullmatch(r"0x[0-9a-f]{64}", value):
        raise ValueError("Invalid resource")
    return value


def iso_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class EmptyBody(StrictBody):
    pass


class LoginBody(StrictBody):
    username: Annotated[str, Field(min_length=1, max_length=80)]
    password: Annotated[str, Field(min_length=1, max_length=256)]


class DeviceBody(StrictBody):
    name: Annotated[str, Field(min_length=1, max_length=80)]


class SimulatorBody(StrictBody):
    resource_id: str
    mode: Literal["normal", "anomaly", "tampered", "replayed", "stale", "malformed", "wrong-device"]
    count: Annotated[int, Field(ge=1, le=20)]
    _resource = field_validator("resource_id")(resource_string)


class KeyBody(StrictBody):
    x25519_public_key_b64: Annotated[str, Field(min_length=44, max_length=44)]
    replace: bool = False


class PolicyBody(StrictBody):
    resource_id: str
    recipient_id: str
    expires_at: Annotated[int, Field(gt=0, le=2**63 - 1)]
    _resource = field_validator("resource_id")(resource_string)
    _recipient = field_validator("recipient_id")(uuid_string)


class SignedReading(StrictBody):
    schema_version: Literal[2]
    resource_id: str
    device_id: str
    sequence: Annotated[int, Field(ge=1, le=2**63 - 1)]
    issued_at: str
    temp_c: Annotated[float, Field(ge=-50, le=200)]
    vibration_mm_s: Annotated[float, Field(ge=0, le=100)]
    rpm: Annotated[int, Field(ge=0, le=20000)]
    signature_b64: Annotated[str, Field(min_length=88, max_length=88)]
    _resource = field_validator("resource_id")(resource_string)
    _device = field_validator("device_id")(uuid_string)

    @field_validator("issued_at")
    @classmethod
    def timestamp(cls, value: str) -> str:
        if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", value):
            raise ValueError("UTC milliseconds required")
        datetime.fromisoformat(value)
        return value
