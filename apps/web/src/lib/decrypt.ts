// Subscriber envelope decryption (PG-041). Browser-only.
// KDF contract — must match the gateway envelope path per DESIGN.md 7
// (apps/gateway/src/privacygate/services/delivery.py +
//  apps/gateway/src/privacygate/security/envelopes.py):
//   shared = X25519(priv, ephemeral_pub);
//   info = "privacygate-envelope-v1|" + canonicalJson(
//     {event_id, key_epoch, policy_version, recipient_wallet, resource_id});
//   key = HKDF-SHA256(salt=32 zero bytes (== Python HKDF salt=None),
//   info, L=32);
//   pt = AES-256-GCM(key, nonce12, aad=AAD bytes).
// SECURITY: private key lives in module memory only. This module never touches
// localStorage/sessionStorage/cookies — grep for "Storage" must stay empty.

import {
  assertEnvelopeShape,
  assertInsightV1,
  b64ToBytes,
  bytesToB64,
  canonicalJson,
  parseAad,
} from "./schemas";
import type { AadContext } from "./schemas";
import type { EnvelopeV1, InsightV1 } from "./api";

let heldPrivateKey: Uint8Array | null = null;

export function setSessionPrivateKey(b64: string): Uint8Array {
  heldPrivateKey = b64ToBytes(b64, 32, "private key");
  return priv().slice();
}

export function hasSessionPrivateKey(): boolean {
  return heldPrivateKey !== null;
}

/** Return key material only when the user explicitly requests a backup export. */
export function exportSessionPrivateKeyB64(): string {
  return bytesToB64(priv());
}

/** Forget key on logout/unload. Call on pagehide too. */
export function clearSessionPrivateKey(): void {
  heldPrivateKey?.fill(0);
  heldPrivateKey = null;
}

function priv(): Uint8Array {
  if (!heldPrivateKey) throw new Error("NO_PRIVATE_KEY: generate or import key first");
  return heldPrivateKey;
}

async function x25519() {
  return (await import("@noble/curves/ed25519")).x25519;
}

export async function generateKeypair(): Promise<{ publicKeyB64: string; privateKeyB64: string }> {
  const x = await x25519();
  const sk = x.utils.randomPrivateKey();
  const pk = x.getPublicKey(sk);
  heldPrivateKey = sk;
  return { publicKeyB64: bytesToB64(pk), privateKeyB64: bytesToB64(sk) };
}

export async function sessionPublicKeyB64(): Promise<string> {
  const x = await x25519();
  return bytesToB64(x.getPublicKey(priv()));
}

const HKDF_DOMAIN = "privacygate-envelope-v1|";
// Python cryptography HKDF(salt=None) uses a HashLen-length zero string;
// for SHA-256 that is 32 zero bytes — pass them explicitly (WebCrypto
// has no None equivalent, and an empty salt would derive a different key).
const HKDF_SALT_ZEROS = new Uint8Array(32);

/** Context-bound HKDF info per DESIGN.md 7; byte-identical to Python canonical_json. */
export function hkdfInfoBytes(ctx: Pick<AadContext, "event_id" | "key_epoch" | "policy_version" | "recipient_wallet" | "resource_id">): Uint8Array {
  const canonical = canonicalJson({
    event_id: ctx.event_id,
    key_epoch: ctx.key_epoch,
    policy_version: ctx.policy_version,
    recipient_wallet: ctx.recipient_wallet.toLowerCase(),
    resource_id: ctx.resource_id,
  });
  return new TextEncoder().encode(HKDF_DOMAIN + canonical);
}

/** Fresh ArrayBuffer-backed copy: satisfies WebCrypto BufferSource typing. */
function fresh(u: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(u.length);
  out.set(u);
  return out;
}

async function deriveKey(sharedSecret: Uint8Array, ctx: AadContext): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey("raw", fresh(sharedSecret), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: fresh(HKDF_SALT_ZEROS), info: fresh(hkdfInfoBytes(ctx)) },
    ikm,
    256,
  );
  return crypto.subtle.importKey("raw", bits, "AES-GCM", false, ["decrypt"]);
}

/** Decrypt one envelope; verifies AAD context + strict 5-field insight. Never returns raw telemetry. */
export async function decryptEnvelope(env: EnvelopeV1): Promise<InsightV1> {
  assertEnvelopeShape(env as unknown as Record<string, unknown>);
  const { ctx, raw: aadRaw } = parseAad(env.aad_b64);
  // AAD context must match envelope header + our session wallet view.
  if (
    ctx.delivery_id !== env.delivery_id ||
    ctx.resource_id !== env.resource_id ||
    ctx.recipient_wallet.toLowerCase() !== env.recipient_wallet.toLowerCase() ||
    ctx.policy_version !== env.policy_version ||
    ctx.key_epoch !== env.key_epoch ||
    ctx.schema_version !== env.schema_version
  )
    throw new Error("AAD_MISMATCH: envelope header differs from authenticated context");
  const x = await x25519();
  const shared = x.getSharedSecret(priv(), b64ToBytes(env.ephemeral_public_key_b64, 32, "ephemeral key"));
  const key = await deriveKey(shared, ctx);
  const nonce = fresh(b64ToBytes(env.nonce_b64, 12, "nonce"));
  const ct = fresh(b64ToBytes(env.ciphertext_b64, atob(env.ciphertext_b64).length, "ciphertext"));
  let pt: ArrayBuffer;
  try {
    pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: fresh(aadRaw) }, key, ct);
  } catch {
    throw new Error("DECRYPT_FAILED: wrong key, rotated epoch, or tampered envelope");
  }
  const insight = assertInsightV1(JSON.parse(new TextDecoder().decode(pt)));
  if (insight.event_id !== ctx.event_id) throw new Error("AAD_MISMATCH: event_id");
  return insight;
}
