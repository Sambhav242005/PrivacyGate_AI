// PG-041 guard checks: strict 5-field insight boundary + envelope/AAD shape.
// Run: node --test tests/  (from apps/web; no deps, imports pure schemas.ts)
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  assertEnvelopeShape,
  assertInsightV1,
  b64ToBytes,
  bytesToB64,
  parseAad,
} from "../src/lib/schemas.ts";

const GOOD_INSIGHT = {
  event_id: "c0b3ec22-2bce-4291-a654-5b8c21663045",
  event_type: "MACHINE_ANOMALY",
  severity: "HIGH",
  observed_at: "2026-10-14T12:00:00.000Z",
  model_version: "isolation-forest-v1",
};

describe("subscriber disclosure boundary", () => {
  it("accepts golden insight-v1 fixture shape", () => {
    assert.deepEqual(assertInsightV1(structuredClone(GOOD_INSIGHT)), GOOD_INSIGHT);
  });

  it("rejects raw telemetry / extra fields", () => {
    for (const extra of [
      { temp_c: 93.2 },
      { vibration_mm_s: 7.1 },
      { rpm: 1450 },
      { telemetry: {} },
      { device_id: "x" },
      { score: 0.99 },
    ]) {
      assert.throws(() => assertInsightV1({ ...GOOD_INSIGHT, ...extra }), /FORBIDDEN|MISMATCH/);
    }
  });

  it("rejects bad enums / timestamps", () => {
    assert.throws(() => assertInsightV1({ ...GOOD_INSIGHT, severity: "CRITICAL" }));
    assert.throws(() => assertInsightV1({ ...GOOD_INSIGHT, event_type: "OTHER" }));
    assert.throws(() => assertInsightV1({ ...GOOD_INSIGHT, observed_at: "yesterday" }));
  });

  it("enforces 32-byte keys, 12-byte nonces", () => {
    assert.throws(() => b64ToBytes(bytesToB64(new Uint8Array(16)), 32, "k"), /32 bytes/);
    assert.equal(b64ToBytes(bytesToB64(new Uint8Array(32)), 32, "k").length, 32);
    assert.throws(() => b64ToBytes("!!!not-b64!!!", 32, "k"), /base64/);
  });

  it("parses 7-field AAD context", () => {
    const aad = {
      delivery_id: "b769c092-0d35-4d05-b3b1-24f7326e43b2",
      event_id: GOOD_INSIGHT.event_id,
      key_epoch: 0,
      policy_version: 1,
      recipient_wallet: "0x2222222222222222222222222222222222222222",
      resource_id: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      schema_version: 1,
    };
    const raw = new TextEncoder().encode(JSON.stringify(aad));
    let s = "";
    for (const x of raw) s += String.fromCharCode(x);
    const { ctx } = parseAad(btoa(s));
    assert.equal(ctx.event_id, GOOD_INSIGHT.event_id);
    assert.throws(() => parseAad(btoa(s + "tampered")), /AAD_INVALID/);
  });

  it("rejects malformed envelopes before crypto", () => {
    assert.throws(() => assertEnvelopeShape({}), /missing/);
    assert.throws(() =>
      assertEnvelopeShape({
        delivery_id: "not-a-uuid", schema_version: 1,
        resource_id: "0x00", recipient_wallet: "0x00",
        policy_version: 1, key_epoch: 0,
        ephemeral_public_key_b64: "AA==", nonce_b64: "AA==",
        aad_b64: "AA==", ciphertext_b64: "AA==",
      }),
    );
  });
});
