# packages/shared — Golden DTO Fixtures (PG-003)

Cross-language reference DTOs for telemetry, policy manifest, insight, envelope.
Normative field semantics: `docs/DATA_MODEL.md`, `docs/API.md`.

## Layout

- `json-schema/` — JSON Schema (draft 2020-12): `telemetry-v1`,
  `signed-telemetry-v1`, `policy-manifest-v1`, `insight-v1`, `envelope-v1`.
- `fixtures/` — canonical golden examples (sorted keys, no whitespace):
  `signed-telemetry-v1.json`, `policy-manifest-v1.json`, `insight-v1.json`,
  `envelope-v1.json`, `policy-digest.json`.
- `tests/test_roundtrip.py` — stdlib-only (`json`+`hashlib`) round-trip checks.

## Canonical JSON + digest

```python
import json, hashlib
canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")
digest = "0x" + hashlib.sha256(canonical).hexdigest()  # policy manifest
```

Policy digest = SHA-256 hex (`0x`-prefixed) of canonical `PolicyManifestV1`.
`allowed_fields`/`allowed_event_types` sorted + deduplicated before hashing.

## Rules

- `InsightV1` = exactly 5 fields (`event_id`, `event_type=MACHINE_ANOMALY`,
  `severity`, `observed_at`, `model_version`). No raw telemetry fields.
- Envelope carries ciphertext only; AAD = `schema_version`, `delivery_id`,
  `event_id`, `resource_id`, `recipient_wallet`, `policy_version`, `key_epoch`.
- Base64 = RFC4648 standard, not URL-safe.
- `signature_b64` in the telemetry fixture is a 64-zero-byte placeholder:
  real Ed25519 signatures come from PG-011/device keys, never checked in.

## Verify

```sh
python -m pytest packages/shared/tests -q
# or without pytest:
python packages/shared/tests/test_roundtrip.py
```
