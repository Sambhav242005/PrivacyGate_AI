"use client";

import { useState } from "react";
import {
  ApiError,
  api,
  type DeviceRes,
  type PermissionEvent,
  type PolicyItem,
  type TelemetryRow,
} from "@/lib/api";
import {
  assertDeviceEnroll,
  assertPolicyDraft,
  assertTxHash,
  buildPolicyManifest,
  policyDigestHex,
} from "@/lib/schemas";
import {
  defaultChainId,
  defaultContractAddress,
  hasInjectedWallet,
  loginWithWallet,
  sendGrantTx,
  sendRevokeTx,
} from "@/lib/wallet";

const DEMO_RESOURCE = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DEMO_READER = "0x2222222222222222222222222222222222222222";

function friendly(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.code === "POLICY_DENIED") return "Access denied — not the on-chain owner, or grant inactive.";
    if (err.code === "AUTHZ_UNAVAILABLE" || err.code === "CHAIN_MISMATCH")
      return "Chain state unreachable — failing closed. Owner reads withheld until ownership re-verifies.";
    if (err.code === "TX_NOT_CONFIRMED") return "Transaction not confirmed yet — wait a block, then sync again.";
    return `${err.code}: ${err.message}`;
  }
  return err instanceof Error ? err.message : "Unexpected error";
}

export default function OwnerDashboard() {
  const [wallet, setWallet] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const [resourceId, setResourceId] = useState(DEMO_RESOURCE);
  const [deviceId, setDeviceId] = useState("");
  const [devName, setDevName] = useState("Synthetic compressor A");
  const [pubkey, setPubkey] = useState("");
  const [devices, setDevices] = useState<DeviceRes[]>([]);

  const [rows, setRows] = useState<TelemetryRow[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);

  const [recipient, setRecipient] = useState(DEMO_READER);
  const [expiry, setExpiry] = useState("1800000000");
  const [contract, setContract] = useState(defaultContractAddress());
  const [txHash, setTxHash] = useState("");
  const [policies, setPolicies] = useState<PolicyItem[]>([]);
  const [digestLine, setDigestLine] = useState<string | null>(null);
  const [events, setEvents] = useState<PermissionEvent[]>([]);

  async function login() {
    setBusy("login");
    setError(null);
    setNote(null);
    try {
      if (!hasInjectedWallet()) throw new Error("No injected wallet found. Install MetaMask or similar.");
      setWallet(await loginWithWallet(api));
      setNote(`Session is an HttpOnly cookie — nothing secret kept in localStorage. Chain ID ${defaultChainId()} (local demo).`);
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(null);
    }
  }

  async function logout() {
    try {
      await api.logout();
    } catch {
      /* session already gone */
    }
    setWallet(null);
    setDevices([]);
    setRows([]);
    setPolicies([]);
  }

  async function enroll() {
    setBusy("enroll");
    setError(null);
    setNote(null);
    try {
      assertDeviceEnroll({ resource_id: resourceId.trim(), device_id: deviceId.trim(), name: devName, ed25519_public_key_b64: pubkey.trim() });
      const d = await api.enrollDevice({
        resource_id: resourceId.trim(),
        device_id: deviceId.trim(),
        name: devName,
        ed25519_public_key_b64: pubkey.trim(),
      });
      setNote(`Enrolled ${d.device_id} (${d.status}). Public key only — private keys never accepted.`);
      setDevices((await api.listDevices()).items);
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(null);
    }
  }

  async function loadTelemetry(next?: string | null) {
    setBusy("tele");
    setError(null);
    try {
      const r = await api.telemetry(resourceId.trim(), 50, next ?? undefined);
      setRows((prev) => (next ? [...prev, ...r.items] : r.items));
      setCursor(r.next_cursor);
    } catch (e) {
      setError(`${friendly(e)} Owner-only; the gateway checks chain ownership on every read.`);
    } finally {
      setBusy(null);
    }
  }

  async function createDraft() {
    setBusy("draft");
    setError(null);
    setNote(null);
    setDigestLine(null);
    try {
      const exp = Number(expiry.trim());
      assertPolicyDraft({ resource_id: resourceId.trim(), recipient_wallet: recipient.trim(), expires_at_unix: exp });
      const created = await api.createPolicy({
        resource_id: resourceId.trim(),
        recipient_wallet: recipient.trim(),
        scope: "READ_INSIGHT",
        allowed_event_types: ["MACHINE_ANOMALY"],
        allowed_fields: ["event_id", "event_type", "severity", "observed_at", "model_version"],
        expires_at_unix: exp,
      });
      const manifest = buildPolicyManifest({
        resource_id: resourceId.trim(),
        recipient_wallet: recipient.trim(),
        expires_at_unix: exp,
        policy_revision: created.policy_revision,
      });
      const local = await policyDigestHex(manifest);
      const match = local.toLowerCase() === created.policy_digest.toLowerCase();
      setDigestLine(`Server ${created.policy_digest} · local preview ${local} — ${match ? "MATCH" : "MISMATCH, do not sign"}`);
      setNote(`Draft ${created.policy_id} saved as DRAFT. Sign the grant in your wallet, then sync with the confirmed tx hash.`);
      setPolicies((await api.listPolicies(resourceId.trim())).items);
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(null);
    }
  }

  async function grantAndSync(policyId: string, digest: string) {
    setBusy(policyId);
    setError(null);
    setNote(null);
    try {
      if (!contract.trim()) throw new Error("Set the PermissionRegistry contract address first.");
      const exp = Number(expiry.trim());
      const hash = await sendGrantTx(contract.trim(), resourceId.trim(), recipient.trim(), digest, exp);
      setTxHash(hash);
      setNote(`Grant sent: ${hash}. Syncing after confirmation…`);
      const out = await api.syncPolicy(policyId, hash);
      setNote(`Sync: ${out.status} at block ${out.confirmed_block} (contract v${out.contract_version}).`);
      setPolicies((await api.listPolicies(resourceId.trim())).items);
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(null);
    }
  }

  async function syncOnly(policyId: string) {
    setBusy(policyId);
    setError(null);
    try {
      assertTxHash(txHash.trim());
      const out = await api.syncPolicy(policyId, txHash.trim());
      setNote(`Sync: ${out.status} at block ${out.confirmed_block}.`);
      setPolicies((await api.listPolicies(resourceId.trim())).items);
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(null);
    }
  }

  async function revoke() {
    setBusy("revoke");
    setError(null);
    try {
      if (!contract.trim()) throw new Error("Set the contract address first.");
      const hash = await sendRevokeTx(contract.trim(), resourceId.trim(), recipient.trim());
      setNote(`Revoke sent: ${hash}. Sync a policy to reflect REVOKED. Stops future delivery only — already-decrypted copies cannot be erased.`);
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <header className="hero">
        <h1>Owner <em>dashboard</em></h1>
        <p>
          One signed sensor → local gateway → owner detail vs encrypted third-party insight.
          Raw readings never leave this screen; subscribers only get ciphertext after a
          confirmed on-chain grant.
        </p>
      </header>

      <div className="warn-strip">
        Local academic demo with synthetic data. Revocation stops <em>future</em> delivery —
        it cannot erase what a reader already decrypted.
      </div>

      <section className="card">
        <h2><span className="step">1</span> Wallet login</h2>
        <p className="sub">EIP-191 challenge signed by the owner wallet. Session is an HttpOnly cookie.</p>
        {wallet ? (
          <div className="row">
            <span className="pill ok">CONNECTED</span>
            <span className="addr">{wallet}</span>
            <button className="ghost" onClick={logout}>Log out</button>
          </div>
        ) : (
          <div className="row">
            <button onClick={login} disabled={busy === "login"}>
              {busy === "login" ? "Waiting for signature…" : "Connect wallet"}
            </button>
            <span className="muted">Requires an injected wallet (MetaMask, etc.)</span>
          </div>
        )}
      </section>

      <section className="card">
        <h2><span className="step">2</span> Device enrollment</h2>
        <p className="sub">Register the resource on-chain first, then enroll here. Public key only — never a private key.</p>
        <div className="row" style={{ marginBottom: 10 }}>
          <input type="text" value={resourceId} onChange={(e) => setResourceId(e.target.value)} aria-label="Resource ID" spellCheck={false} />
        </div>
        <div className="row" style={{ marginBottom: 10 }}>
          <input type="text" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} placeholder="device_id (UUID)" aria-label="Device ID" spellCheck={false} />
          <input type="text" value={devName} onChange={(e) => setDevName(e.target.value)} placeholder="name" aria-label="Device name" />
        </div>
        <div className="row">
          <input type="text" value={pubkey} onChange={(e) => setPubkey(e.target.value)} placeholder="ed25519_public_key_b64 (32 bytes, standard base64)" aria-label="Ed25519 public key" spellCheck={false} />
        </div>
        <div className="row" style={{ marginTop: 12 }}>
          <button onClick={enroll} disabled={!wallet || busy === "enroll"}>
            {busy === "enroll" ? "Enrolling…" : "Enroll device"}
          </button>
          <button className="ghost" onClick={() => api.listDevices().then((l) => setDevices(l.items)).catch((e) => setError(friendly(e)))} disabled={!wallet}>
            Refresh devices
          </button>
        </div>
        {devices.map((d) => (
          <p className="mono" key={d.device_id}>{d.device_id} · {d.name} · {d.status}</p>
        ))}
      </section>

      <section className="card">
        <h2><span className="step">3</span> Detailed telemetry <span className="pill">OWNER ONLY</span></h2>
        <p className="sub">Decrypted server-side only for the confirmed on-chain owner. Fails closed on chain outage.</p>
        <div className="row">
          <button onClick={() => loadTelemetry(null)} disabled={!wallet || busy === "tele"}>
            {busy === "tele" ? "Loading…" : rows.length ? "Reload telemetry" : "Load telemetry"}
          </button>
          {cursor && <button className="ghost" onClick={() => loadTelemetry(cursor)}>Load more</button>}
        </div>
        {rows.map((r) => (
          <p className="mono" key={`${r.device_id}-${r.sequence}`}>
            #{r.sequence} · {r.issued_at} · {r.temp_c}°C · {r.vibration_mm_s} mm/s · {r.rpm} rpm
          </p>
        ))}
        {wallet && rows.length === 0 && busy !== "tele" && <p className="muted">No rows yet — run the simulator to publish signed telemetry.</p>}
      </section>

      <section className="card">
        <h2><span className="step">4</span> Policy draft → grant → sync</h2>
        <p className="sub">Scope is always READ_INSIGHT for third parties. The contract stores only the digest.</p>
        <div className="row" style={{ marginBottom: 10 }}>
          <input type="text" value={recipient} onChange={(e) => setRecipient(e.target.value)} aria-label="Recipient wallet" spellCheck={false} />
          <input type="text" value={expiry} onChange={(e) => setExpiry(e.target.value)} aria-label="Expiry unix seconds" inputMode="numeric" />
        </div>
        <div className="row" style={{ marginBottom: 10 }}>
          <input type="text" value={contract} onChange={(e) => setContract(e.target.value)} placeholder="PermissionRegistry contract 0x…" aria-label="Contract address" spellCheck={false} />
          <input type="text" value={txHash} onChange={(e) => setTxHash(e.target.value)} placeholder="tx hash for manual sync 0x…" aria-label="Transaction hash" spellCheck={false} />
        </div>
        <div className="row">
          <button onClick={createDraft} disabled={!wallet || busy === "draft"}>
            {busy === "draft" ? "Saving…" : "Create policy draft"}
          </button>
          <button className="ghost" onClick={() => api.listPolicies(resourceId.trim()).then((l) => setPolicies(l.items)).catch((e) => setError(friendly(e)))} disabled={!wallet}>
            Refresh policies
          </button>
          <button className="danger" onClick={revoke} disabled={!wallet || busy === "revoke"}>
            Revoke grant on-chain
          </button>
        </div>
        {digestLine && <p className="mono">{digestLine}</p>}
        {policies.map((p) => (
          <article className="env" key={p.policy_id}>
            <div className="env-head">
              <span className="mono">{p.policy_id.slice(0, 8)}… rev{p.policy_revision}</span>
              <span className={`pill ${p.status === "ACTIVE" ? "ok" : p.status === "REVOKED" ? "high" : ""}`}>{p.status}</span>
              <span className="mono">{p.policy_digest.slice(0, 18)}…</span>
              <button className="ghost" onClick={() => grantAndSync(p.policy_id, p.policy_digest)} disabled={busy === p.policy_id}>
                {busy === p.policy_id ? "Waiting…" : "Grant + sync"}
              </button>
              <button className="ghost" onClick={() => syncOnly(p.policy_id)} disabled={busy === p.policy_id}>
                Sync tx
              </button>
            </div>
          </article>
        ))}
        <div className="row" style={{ marginTop: 12 }}>
          <button className="ghost" onClick={() => api.permissionEvents(resourceId.trim()).then((r) => setEvents(r.items)).catch((e) => setError(friendly(e)))} disabled={!wallet}>
            Load on-chain events
          </button>
        </div>
        {events.map((v, i) => (
          <p className="mono" key={i}>{v.event_type} · block {v.block_number} · v{v.contract_version} · {v.tx_hash.slice(0, 18)}…</p>
        ))}
      </section>

      {note && <div className="note">{note}</div>}
      {error && <div className="err" role="alert"><code>!</code> {error}</div>}

      <footer className="foot">
        Pending vs confirmed: a wallet tx hash is <em>pending</em> until sync reports ACTIVE/REVOKED
        from confirmed chain state. Subscriber view stays ciphertext-only throughout.
      </footer>
    </>
  );
}
