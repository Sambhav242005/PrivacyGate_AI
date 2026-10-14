// Pure validators mirrored from packages/shared json-schema (insight-v1, envelope-v1).
// Dependency-free so node --test can import this file directly (erasable syntax only).
// The 5-field allowlist is the disclosure boundary: anything else is dropped, never shown.

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const HEX32_RE = /^0x[0-9a-f]{64}$/;
const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const TS_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

export const PERMITTED_INSIGHT_FIELDS = [
  "event_id",
  "event_type",
  "severity",
  "observed_at",
  "model_version",
] as const;
// Raw telemetry fields must NEVER reach the subscriber view.
const FORBIDDEN_FIELDS = ["temp_c", "vibration_mm_s", "rpm", "telemetry", "device_id", "score", "confidence", "prompt", "coordinates", "location"];

export interface InsightV1 {
  event_id: string;
  event_type: "MACHINE_ANOMALY";
  severity: "LOW" | "MEDIUM" | "HIGH";
  observed_at: string;
  model_version: string;
}

export interface AadContext {
  schema_version: number;
  delivery_id: string;
  event_id: string;
  resource_id: string;
  recipient_wallet: string;
  policy_version: number;
  key_epoch: number;
}

/** Strict InsightV1 check: exactly 5 permitted fields, nothing extra. Throws on violation. */
export function assertInsightV1(u: unknown): InsightV1 {
  if (typeof u !== "object" || u === null) throw new Error("INSIGHT_INVALID: not an object");
  const o = u as Record<string, unknown>;
  for (const f of FORBIDDEN_FIELDS) {
    if (f in o) throw new Error(`INSIGHT_FORBIDDEN_FIELD: ${f}`);
  }
  const keys = Object.keys(o).sort();
  const want = [...PERMITTED_INSIGHT_FIELDS].sort();
  if (keys.length !== want.length || !keys.every((k, i) => k === want[i]))
    throw new Error(`INSIGHT_FIELD_MISMATCH: got [${keys.join(",")}]`);
  if (typeof o.event_id !== "string" || !UUID_RE.test(o.event_id)) throw new Error("INSIGHT_INVALID: event_id");
  if (o.event_type !== "MACHINE_ANOMALY") throw new Error("INSIGHT_INVALID: event_type");
  if (o.severity !== "LOW" && o.severity !== "MEDIUM" && o.severity !== "HIGH")
    throw new Error("INSIGHT_INVALID: severity");
  if (typeof o.observed_at !== "string" || !TS_RE.test(o.observed_at))
    throw new Error("INSIGHT_INVALID: observed_at");
  if (typeof o.model_version !== "string" || o.model_version.length < 1 || o.model_version.length > 64)
    throw new Error("INSIGHT_INVALID: model_version");
  return o as unknown as InsightV1;
}

export function b64ToBytes(s: string, expectBytes: number, label: string): Uint8Array {
  let bin: string;
  try {
    bin = atob(s);
  } catch {
    throw new Error(`${label}: not standard base64`);
  }
  if (bin.length !== expectBytes) throw new Error(`${label}: want ${expectBytes} bytes, got ${bin.length}`);
  const out = new Uint8Array(expectBytes);
  for (let i = 0; i < expectBytes; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

/** Decode + validate the 7-field AAD context. Caller must compare against envelope. */
export function parseAad(aad_b64: string): { ctx: AadContext; raw: Uint8Array } {
  const raw = b64ToBytes(aad_b64, atob(aad_b64).length, "AAD");
  let o: Record<string, unknown>;
  try {
    o = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    throw new Error("AAD_INVALID: not JSON");
  }
  const keys = Object.keys(o).sort();
  const want = ["delivery_id", "event_id", "key_epoch", "policy_version", "recipient_wallet", "resource_id", "schema_version"].sort();
  if (keys.length !== want.length || !keys.every((k, i) => k === want[i]))
    throw new Error("AAD_INVALID: field set");
  if (o.schema_version !== 1) throw new Error("AAD_INVALID: schema_version");
  if (typeof o.delivery_id !== "string" || !UUID_RE.test(o.delivery_id)) throw new Error("AAD_INVALID: delivery_id");
  if (typeof o.event_id !== "string" || !UUID_RE.test(o.event_id)) throw new Error("AAD_INVALID: event_id");
  if (typeof o.resource_id !== "string" || !HEX32_RE.test(o.resource_id)) throw new Error("AAD_INVALID: resource_id");
  if (typeof o.recipient_wallet !== "string" || !ADDR_RE.test(o.recipient_wallet))
    throw new Error("AAD_INVALID: recipient_wallet");
  if (!Number.isInteger(o.policy_version) || (o.policy_version as number) < 1) throw new Error("AAD_INVALID: policy_version");
  if (!Number.isInteger(o.key_epoch) || (o.key_epoch as number) < 0) throw new Error("AAD_INVALID: key_epoch");
  return { ctx: o as unknown as AadContext, raw };
}

/** Envelope header shape check before any crypto (lengths of b64 fields). */
export function assertEnvelopeShape(e: Record<string, unknown>): void {  const req = ["delivery_id", "schema_version", "resource_id", "recipient_wallet", "policy_version", "key_epoch", "ephemeral_public_key_b64", "nonce_b64", "aad_b64", "ciphertext_b64"];
  for (const k of req) if (!(k in e)) throw new Error(`ENVELOPE_INVALID: missing ${k}`);
  if (typeof e.delivery_id !== "string" || !UUID_RE.test(e.delivery_id)) throw new Error("ENVELOPE_INVALID: delivery_id");
  if (e.schema_version !== 1) throw new Error("ENVELOPE_INVALID: schema_version");
  if (typeof e.resource_id !== "string" || !HEX32_RE.test(e.resource_id)) throw new Error("ENVELOPE_INVALID: resource_id");
  b64ToBytes(e.ephemeral_public_key_b64 as string, 32, "ephemeral key");
  b64ToBytes(e.nonce_b64 as string, 12, "nonce");
}

// ---- Owner lane (PG-040): device enroll + policy draft validators/digest ----
// Mirrors packages/shared/json-schema/{signed-telemetry,policy-manifest}-v1.json.
// Server re-validates; these only catch typos before a signed request.

const RES_LOWER_RE = /^0x[0-9a-f]{64}$/;
const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;

function isB64OfBytes(v: string, nbytes: number): boolean {
  try {
    b64ToBytes(v, nbytes, "check");
    return true;
  } catch {
    return false;
  }
}

export function assertDeviceEnroll(d: {
  resource_id: string;
  device_id: string;
  name: string;
  ed25519_public_key_b64: string;
}): void {
  if (!RES_LOWER_RE.test(d.resource_id)) throw new Error("resource_id must be 0x + 64 lowercase hex");
  if (!UUID_RE.test(d.device_id)) throw new Error("device_id must be UUID");
  if (!d.name || d.name.length > 128) throw new Error("name must be 1..128 chars");
  if (!isB64OfBytes(d.ed25519_public_key_b64, 32))
    throw new Error("ed25519_public_key_b64 must be standard base64 of 32 bytes");
}

export function assertPolicyDraft(d: {
  resource_id: string;
  recipient_wallet: string;
  expires_at_unix: number;
}): void {
  if (!RES_LOWER_RE.test(d.resource_id)) throw new Error("resource_id must be 0x + 64 lowercase hex");
  if (!ADDR_RE.test(d.recipient_wallet)) throw new Error("recipient must be 0x + 40 hex");
  if (!Number.isInteger(d.expires_at_unix) || d.expires_at_unix <= 0)
    throw new Error("expires_at_unix must be a positive integer (Unix seconds)");
}

export function assertTxHash(h: string): void {
  if (!TX_HASH_RE.test(h)) throw new Error("transaction_hash must be 0x + 64 hex");
}

export interface PolicyManifestV1 {
  resource_id: string;
  recipient_wallet_lowercase: string;
  scope: "READ_INSIGHT";
  allowed_event_types: ["MACHINE_ANOMALY"];
  allowed_fields: string[];
  expires_at_unix: number;
  policy_revision: number;
}

export function buildPolicyManifest(d: {
  resource_id: string;
  recipient_wallet: string;
  expires_at_unix: number;
  policy_revision: number;
}): PolicyManifestV1 {
  return {
    resource_id: d.resource_id,
    recipient_wallet_lowercase: d.recipient_wallet.toLowerCase(),
    scope: "READ_INSIGHT",
    allowed_event_types: ["MACHINE_ANOMALY"],
    allowed_fields: [...PERMITTED_INSIGHT_FIELDS].sort(),
    expires_at_unix: d.expires_at_unix,
    policy_revision: d.policy_revision,
  };
}

/** Canonical JSON: sorted keys, no whitespace. Server digest is authoritative. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`)
    .join(",")}}`;
}

/** Local digest preview (SHA-256 of canonical manifest). Must equal server digest. */
export async function policyDigestHex(m: PolicyManifestV1): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalJson(m));
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return "0x" + [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

