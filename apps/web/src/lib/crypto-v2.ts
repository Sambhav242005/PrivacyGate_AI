"use client";

import { apiV2, type EnvelopeV2, type Insight } from "./api-v2";

const encoder = new TextEncoder();
let privateBytes: Uint8Array<ArrayBuffer> | null = null;
let currentAccount: string | null = null;

async function x25519() {
  return (await import("@noble/curves/ed25519")).x25519;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string, expectedLength?: number): Uint8Array {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("Invalid base64 in encrypted insight.");
  }
  const bytes = Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  if (expectedLength !== undefined && bytes.length !== expectedLength) {
    throw new Error(`Expected ${expectedLength} bytes in encrypted insight.`);
  }
  return bytes;
}

function canonical(value: unknown): string {
  return JSON.stringify(value, Object.keys(value as object).sort());
}

function exactObject(value: unknown, fields: string[], name: string): asserts value is Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join("|") !== [...fields].sort().join("|")
  ) {
    throw new Error(`${name} has missing or unknown fields.`);
  }
}

/** Give WebCrypto an ArrayBuffer-backed view rather than a possibly shared buffer. */
function fresh(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy;
}

export function clearReaderKey(): void {
  privateBytes?.fill(0);
  privateBytes = null;
  currentAccount = null;
}

export function hasReaderKey(accountId: string): boolean {
  return privateBytes !== null && currentAccount === accountId;
}

export async function createReaderKey(accountId: string): Promise<{ public_key_b64: string; backup: string }> {
  const curve = await x25519();
  const secret = curve.utils.randomPrivateKey();
  const publicKey = curve.getPublicKey(secret);
  privateBytes = fresh(secret);
  currentAccount = accountId;

  const publicKeyB64 = toBase64(publicKey);
  const backup = JSON.stringify(
    {
      schema_version: 2,
      account_id: accountId,
      public_key_b64: publicKeyB64,
      private_key_b64: toBase64(secret),
    },
    null,
    2,
  );
  return { public_key_b64: publicKeyB64, backup };
}

export async function importReaderBackup(raw: string, accountId: string): Promise<string> {
  if (raw.length > 4096) throw new Error("Backup file is too large.");

  let backup: unknown;
  try {
    backup = JSON.parse(raw);
  } catch {
    throw new Error("Backup must be valid JSON.");
  }
  exactObject(backup, ["schema_version", "account_id", "public_key_b64", "private_key_b64"], "Backup");

  if (backup.schema_version !== 2 || backup.account_id !== accountId) {
    throw new Error("This backup belongs to a different account or schema version.");
  }

  const secret = fromBase64(String(backup.private_key_b64), 32);
  const publicKey = fromBase64(String(backup.public_key_b64), 32);
  const derivedPublicKey = (await x25519()).getPublicKey(secret);
  if (derivedPublicKey.some((byte, index) => byte !== publicKey[index])) {
    throw new Error("Backup public key does not match its private key.");
  }

  privateBytes = fresh(secret);
  currentAccount = accountId;
  return toBase64(publicKey);
}

export async function decryptV2(
  envelope: EnvelopeV2,
  accountId: string,
  resourceId: string,
): Promise<Insight> {
  if (!hasReaderKey(accountId)) throw new Error("Restore the viewing key for this account first.");

  exactObject(
    envelope,
    [
      "schema_version", "delivery_id", "resource_id", "recipient_id", "policy_version",
      "key_version", "key_epoch", "ephemeral_public_key_b64", "nonce_b64", "aad_b64",
      "ciphertext_b64",
    ],
    "Envelope",
  );
  if (envelope.schema_version !== 2 || envelope.recipient_id !== accountId || envelope.resource_id !== resourceId) {
    throw new Error("Encrypted insight account or equipment does not match this view.");
  }

  const aad = fromBase64(envelope.aad_b64);
  let context: unknown;
  try {
    context = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(aad));
  } catch {
    throw new Error("Encrypted insight metadata is invalid.");
  }
  exactObject(
    context,
    [
      "schema_version", "delivery_id", "event_id", "resource_id", "recipient_id",
      "policy_version", "key_version", "key_epoch",
    ],
    "Authenticated metadata",
  );

  const ctx = context;
  const rawAad = new TextDecoder().decode(aad);
  if (
    canonical(ctx) !== rawAad ||
    ctx.schema_version !== 2 ||
    ctx.delivery_id !== envelope.delivery_id ||
    ctx.resource_id !== resourceId ||
    ctx.recipient_id !== accountId ||
    ctx.policy_version !== envelope.policy_version ||
    ctx.key_version !== envelope.key_version ||
    ctx.key_epoch !== envelope.key_epoch
  ) {
    throw new Error("Encrypted insight metadata does not match its envelope.");
  }

  const infoContext = {
    event_id: ctx.event_id,
    key_epoch: ctx.key_epoch,
    key_version: ctx.key_version,
    policy_version: ctx.policy_version,
    recipient_id: accountId,
    resource_id: resourceId,
  };
  const info = fresh(encoder.encode(`privacygate-envelope-v2|${canonical(infoContext)}`));
  const curve = await x25519();
  const sharedSecret = curve.getSharedSecret(
    privateBytes!,
    fromBase64(envelope.ephemeral_public_key_b64, 32),
  );
  const keyMaterial = await crypto.subtle.importKey("raw", fresh(sharedSecret), "HKDF", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: fresh(new Uint8Array(32)), info },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fresh(fromBase64(envelope.nonce_b64, 12)),
        additionalData: fresh(aad),
      },
      aesKey,
      fresh(fromBase64(envelope.ciphertext_b64)),
    );
  } catch {
    throw new Error("Decryption failed. The backup may be wrong or this envelope may be damaged.");
  }

  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
  } catch {
    throw new Error("Decrypted insight is not valid JSON.");
  }
  exactObject(value, ["event_id", "event_type", "severity", "observed_at", "model_version"], "Decrypted insight");

  if (
    value.event_id !== ctx.event_id ||
    value.event_type !== "MACHINE_ANOMALY" ||
    !["LOW", "MEDIUM", "HIGH"].includes(String(value.severity)) ||
    typeof value.observed_at !== "string" ||
    !Number.isFinite(Date.parse(value.observed_at)) ||
    typeof value.model_version !== "string"
  ) {
    throw new Error("Decrypted insight content is invalid.");
  }
  return value as unknown as Insight;
}

export async function enrollReaderKey(accountId: string) {
  const generated = await createReaderKey(accountId);
  const key = await apiV2.registerKey(generated.public_key_b64);
  return { ...generated, key };
}
