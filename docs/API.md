# API.md — HTTP, MQTT and Blockchain Interface Contract

> **Contract status: proposed v1, implementation pending.** All HTTP routes start `/v1` and accept/respond JSON unless specified. The source of truth for business meaning is `SPEC.md`; exact data shape is `DATA_MODEL.md`.

## 1. Transport and authentication

- Local gateway base URL: `http://127.0.0.1:8000`; frontend: `http://127.0.0.1:3000`; TLS **required outside loopback**.
- Owner and subscriber authenticate with EIP-191 wallet `personal_sign` challenge, server-side nonce (single-use, TTL 5m), audience, domain, chain ID, wallet address. Success sets HttpOnly `pg_session` cookie with Secure in production; SameSite=Lax or Strict. Add `X-CSRF-Token` to cookie-authenticated mutations, check Origin, and require `credentials: include` from the frontend.
- Access is always checked on gateway routes, not inferred from UI screen.
- All timestamps in REST are ISO8601 UTC `Z`; all bytes/base64 use **RFC4648 standard base64**, not URL-safe variant. Binary contract hashes/IDs are lowercase `0x` hex in HTTP responses except displayed wallet checksums.
- All request models reject unknown fields; response serializers must not include raw local/internal data.

### Standard error object

```json
{
  "error": {
    "code": "POLICY_DENIED",
    "message": "This action is not authorized",
    "request_id": "7b8974ac-d745-4cd2-9ae2-1dbf1d8b8cc1"
  }
}
```

Codes: `INVALID_INPUT` (400/422), `NOT_AUTHENTICATED` (401), `POLICY_DENIED` (403), `RESOURCE_NOT_FOUND` (404), `ALREADY_EXISTS` (409), `REPLAY_DETECTED` (409), `TX_NOT_CONFIRMED` (409), `CHAIN_MISMATCH` (503), `AUTHZ_UNAVAILABLE` (503), `KEY_NOT_REGISTERED` (409), `RATE_LIMITED` (429). Mask ownership-sensitive resource IDs using 404 when appropriate.

## 2. Wallet login/session

### `POST /v1/auth/challenge`

Request:

```json
{ "wallet_address": "0x1111111111111111111111111111111111111111" }
```

200 response:

```json
{
  "challenge_id": "cd50dc9f-e780-4054-98fd-7502e971b8af",
  "message_to_sign": "PrivacyGate AI login\nDomain: localhost\nChain ID: 31337\nWallet: 0x1111111111111111111111111111111111111111\nNonce: <random-single-use>\nIssued At: <UTC>\nExpires At: <UTC>",
  "expires_at": "2026-10-14T12:05:00.000Z"
}
```

Challenge message format must be assembled server-side (values above illustrate shape, not an actual valid challenge). Always bind domain/audience, nonce, wallet and chain ID to prevent cross-site/chain replay.

### `POST /v1/auth/verify`

```json
{
  "challenge_id": "cd50dc9f-e780-4054-98fd-7502e971b8af",
  "signature_hex": "0x<65-byte-EIP191-signature>"
}
```

200 response sets `pg_session` cookie; JSON contains `wallet_address`, `expires_at`, `csrf_token`. Verification must atomically consume challenge even under concurrent requests. Bad/expired/reused = 401.

- `GET /v1/me` → wallet, roles derived from resources/grants, session expiration; no sensitive keys.
- `POST /v1/auth/logout` → expires cookie and server session.

## 3. Resource and device management (owner only)

### `POST /v1/devices`

Precondition: caller is confirmed `ownerOf(resource_id)` on configured chain; resource is registered first via wallet `registerResource(bytes32)` transaction. Request:

```json
{
  "resource_id": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "device_id": "30ad1113-88be-44fd-90fd-683d0a3dd7b0",
  "name": "Synthetic compressor A",
  "ed25519_public_key_b64": "<base64-of-32-public-key-bytes>"
}
```

201 response: `resource_id`, `device_id`, `name`, `registered_at`, `status: "ACTIVE"`. No private key may ever be accepted.

- `GET /v1/devices` → owner's registered devices only.
- `GET /v1/resources/{resource_id}/telemetry?limit=100&cursor=...` → **owner only**; `{ "items": [{"device_id","sequence","issued_at","temp_c","vibration_mm_s","rpm"}], "next_cursor": null }`; validate `limit <= 100`. No public telemetry endpoint.

## 4. Recipient encryption-key enrollment

### `POST /v1/keys`

Authenticated subscriber or owner registers their **own** X25519 public key:

```json
{
  "x25519_public_key_b64": "<base64-of-32-public-key-bytes>"
}
```

200 response: `{ "wallet_address": "0x...", "key_id": "<uuid>", "registered_at": "<UTC>" }`. Ownership is bound to authenticated wallet session. Key rotations invalidate undelivered envelopes for that reader and require regenerating future deliveries. Never submit private key material.

## 5. Owner policy lifecycle

### `POST /v1/policies` — create local policy draft

Owner must own `resource_id`. Request:

```json
{
  "resource_id": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "recipient_wallet": "0x2222222222222222222222222222222222222222",
  "scope": "READ_INSIGHT",
  "allowed_event_types": ["MACHINE_ANOMALY"],
  "allowed_fields": ["event_id", "event_type", "severity", "observed_at", "model_version"],
  "expires_at_unix": 1800000000
}
```

201 response:

```json
{
  "policy_id": "7d2c487f-1963-47c3-9384-ce92982d04aa",
  "policy_revision": 1,
  "policy_digest": "0x<64-lowercase-hex>",
  "status": "DRAFT",
  "onchain_grant_required": true
}
```

- Allowlisted scopes in MVP: `READ_INSIGHT` only for third parties. Owner gets `READ_DETAIL` through ownership, not by creating third-party grants.
- Canonical digest fields are precisely `{resource_id,recipient_wallet_lowercase,scope,allowed_event_types,allowed_fields,expires_at_unix,policy_revision}`. Normalize arrays lexicographically and recipient address lowercase **before** SHA-256 canonicalization. Unknown/event-extra fields forbidden.
- Owner then calls contract `grant(resourceId, readerWallet, policyDigest, expiresAtUnix)` from their wallet and waits for confirmed receipt.

### `POST /v1/policies/{policy_id}/sync`

Request: `{ "transaction_hash": "0x<64-hex>" }`. Gateway validates tx receipt `status=1`, configured chain ID and contract address, matching resource/reader/digest, confirmed block and current grant view. Activation/revocation determined **from confirmed on-chain state**, not from request intent. Idempotent response:

```json
{
  "policy_id": "7d2c487f-1963-47c3-9384-ce92982d04aa",
  "status": "ACTIVE",
  "contract_version": 1,
  "confirmed_block": 8,
  "transaction_hash": "0x<64-hex>"
}
```

When a confirmed owner `revoke(resourceId, reader)` is detected, status becomes `REVOKED`, unread envelopes are no longer served and `key_epoch` increments. No public mutation route can grant permission without a real owner-signed transaction.

- `GET /v1/policies?resource_id=...` → owner-only local drafts and chain-sync status. Never disclose recipient list to other subscribers.

## 6. Encrypted insight retrieval (subscriber)

### `GET /v1/insights?resource_id=0x...&limit=50&cursor=...`

Preconditions: authenticated wallet; currently confirmed active `READ_INSIGHT` grant; exact local policy hash and expiry check; recipient X25519 key registered; chain available **now**. Request may return `503 AUTHZ_UNAVAILABLE` if RPC cannot be validated. Use `limit <= 100`.

200 response:

```json
{
  "items": [
    {
      "delivery_id": "b769c092-0d35-4d05-b3b1-24f7326e43b2",
      "schema_version": 1,
      "resource_id": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "recipient_wallet": "0x2222222222222222222222222222222222222222",
      "policy_version": 1,
      "key_epoch": 0,
      "ephemeral_public_key_b64": "<base64-32-byte-X25519-key>",
      "nonce_b64": "<base64-12-byte-nonce>",
      "aad_b64": "<base64-canonical-envelope-header>",
      "ciphertext_b64": "<base64-ciphertext-with-AESGCM-tag>"
    }
  ],
  "next_cursor": null
}
```

The encrypted plaintext is **exactly**:

```json
{
  "event_id": "c0b3ec22-2bce-4291-a654-5b8c21663045",
  "event_type": "MACHINE_ANOMALY",
  "severity": "HIGH",
  "observed_at": "2026-10-14T12:00:00.000Z",
  "model_version": "isolation-forest-v1"
}
```

Subscriber derives the symmetric key via ephemeral X25519 → HKDF and decrypts AES-GCM using authenticated AAD. AAD has canonical fields: `schema_version`, `delivery_id`, `event_id`, `resource_id`, `recipient_wallet`, `policy_version`, `key_epoch`. Verify AAD context after decoding, before displaying result. **No plaintext insight from this endpoint.**

### `GET /v1/audit/permission-events?resource_id=...`

Owner only. Returns confirmed on-chain grant/revoke summaries (`event_type`, `block_number`, `tx_hash`, `contract_version`, `observed_at`) with `next_cursor`. Do not return private policy JSON or telemetry through this route.

### `GET /v1/health` and `GET /v1/ready`

Health: process is alive; readiness: dependent services states (`gateway`, `database`, `mqtt`, `chain`), without exposing secret configuration. A chain outage makes third-party delivery unavailable but does not imply telemetry ingestion is unavailable.

## 7. MQTT topic and signed payload

Topic: `devices/{device_id}/telemetry` | QoS: 1 | `retain: false` | maximum payload: 4096 bytes.

```json
{
  "schema_version": 1,
  "device_id": "30ad1113-88be-44fd-90fd-683d0a3dd7b0",
  "resource_id": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "sequence": 1,
  "issued_at": "2026-10-14T12:00:00.000Z",
  "telemetry": {"temp_c": 93.2, "vibration_mm_s": 7.1, "rpm": 1450},
  "signature_b64": "<base64-64-byte-Ed25519-signature>"
}
```

Signature covers all fields **except** `signature_b64`. Timestamp skew allowed ±30s by default, sequence must increase atomically per device. Telemetry bounds detailed in `DATA_MODEL.md`. Device private key must never leave simulator/device. Broker topic ACL plus gateway validation are required.

## 8. Smart contract boundary

`PermissionRegistry.sol`:

```solidity
function registerResource(bytes32 resourceId) external;
function grant(bytes32 resourceId, address reader, bytes32 policyDigest, uint64 expiresAt) external;
function revoke(bytes32 resourceId, address reader) external;
function ownerOf(bytes32 resourceId) external view returns (address);
function getGrant(bytes32 resourceId, address reader) external view
    returns (bytes32 policyDigest, uint64 expiresAt, uint32 version, bool active, uint8 scope);
```

`scope=1` represents `READ_INSIGHT`; a grant cannot grant `READ_DETAIL` in MVP. Events: `ResourceRegistered`, `GrantSet`, `GrantRevoked`, each includes resource and owner/reader identifiers plus version where applicable. Changes to Solidity ABI **must** update all clients, tests and these docs in one PR.

## 9. API negative test checklist

- Unauthenticated / unknown resource / wrong wallet / expired grant.
- Old confirmed but superseded grant; mismatched policy digest.
- Missing registered recipient encryption key; stale chain; wrong chain ID.
- Unexpected input/model fields; tampered EIP-191 challenge, replay.
- Arbitrary `transaction_hash` claiming a grant never enacted.
- Verify subscriber payload contains **only encrypted envelope** until locally decrypted.
