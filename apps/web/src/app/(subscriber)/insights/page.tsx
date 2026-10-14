"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api, type EnvelopeV1, type InsightV1 } from "@/lib/api";
import { hasInjectedWallet, loginWithWallet } from "@/lib/wallet";
import {
  clearSessionPrivateKey,
  decryptEnvelope,
  generateKeypair,
  sessionPublicKeyB64,
  setSessionPrivateKey,
} from "@/lib/decrypt";
import { b64ToBytes } from "@/lib/schemas";

const POLL_MS = 15_000;
const DEMO_RESOURCE = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function friendly(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.code === "POLICY_DENIED") return "Access denied — grant revoked, expired, or never issued. No new envelopes will arrive.";
    if (err.code === "AUTHZ_UNAVAILABLE") return "Chain state unreachable — failing closed. Envelopes withheld until authorization can be re-verified.";
    if (err.code === "KEY_NOT_REGISTERED") return "No encryption key enrolled for this wallet. Complete step 2 first.";
    return `${err.code}: ${err.message}`;
  }
  return err instanceof Error ? err.message : "Unexpected error";
}

export default function SubscriberInsightsPage() {
  const [wallet, setWallet] = useState<string | null>(null);
  const [pubB64, setPubB64] = useState<string | null>(null);
  const [hasKey, setHasKey] = useState(false);
  const [resourceId, setResourceId] = useState(DEMO_RESOURCE);
  const [items, setItems] = useState<EnvelopeV1[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [insights, setInsights] = useState<Record<string, InsightV1>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [importB64, setImportB64] = useState("");
  const poll = useRef<ReturnType<typeof setInterval> | null>(null);

  // Never persist secrets: clear memory key on hide/unmount.
  useEffect(() => {
    const clear = () => clearSessionPrivateKey();
    window.addEventListener("pagehide", clear);
    return () => {
      window.removeEventListener("pagehide", clear);
      clearSessionPrivateKey();
    };
  }, []);

  const login = useCallback(async () => {
    setBusy("login"); setError(null);
    try {
      if (!hasInjectedWallet()) throw new Error("No injected wallet found. Install MetaMask or similar.");
      setWallet(await loginWithWallet(api));
    } catch (e) { setError(friendly(e)); } finally { setBusy(null); }
  }, []);

  const logout = useCallback(async () => {
    try { await api.logout(); } catch { /* session already gone */ }
    clearSessionPrivateKey();
    if (poll.current) clearInterval(poll.current);
    setWallet(null); setHasKey(false); setPubB64(null); setItems([]); setInsights({}); setCursor(null); setDone(false);
  }, []);

  /** Generate fresh X25519 pair in memory, enroll public key wallet-bound via POST /v1/keys. */
  const enrollFresh = useCallback(async () => {
    setBusy("enroll"); setError(null);
    try {
      const { publicKeyB64 } = await generateKeypair();
      b64ToBytes(publicKeyB64, 32, "public key"); // 32-byte guard before upload
      await api.registerKey(publicKeyB64);
      setPubB64(publicKeyB64); setHasKey(true);
    } catch (e) { clearSessionPrivateKey(); setError(friendly(e)); } finally { setBusy(null); }
  }, []);

  /** Re-enter an existing private key (memory only, explicit user action). */
  const importExisting = useCallback(async () => {
    setBusy("import"); setError(null);
    try {
      setSessionPrivateKey(importB64.trim());
      const pub = await sessionPublicKeyB64();
      await api.registerKey(pub); // re-bind current key epoch to this wallet
      setPubB64(pub); setHasKey(true); setImportB64("");
    } catch (e) { clearSessionPrivateKey(); setError(friendly(e)); } finally { setBusy(null); }
  }, [importB64]);

  const fetchPage = useCallback(async (cur: string | null, append: boolean) => {
    setBusy("fetch"); setError(null);
    try {
      const page = await api.listInsights(resourceId.trim(), 50, cur ?? undefined);
      setItems((prev) => (append ? [...prev, ...page.items] : page.items));
      setCursor(page.next_cursor); setDone(page.next_cursor == null);
    } catch (e) { setError(friendly(e)); } finally { setBusy(null); }
  }, [resourceId]);

  // Polling envelope list while logged in with a resource selected.
  useEffect(() => {
    if (poll.current) clearInterval(poll.current);
    if (!wallet || !resourceId) return;
    void fetchPage(null, false);
    poll.current = setInterval(() => { void fetchPage(null, false); }, POLL_MS);
    return () => { if (poll.current) clearInterval(poll.current); };
  }, [wallet, resourceId, fetchPage]);

  const decryptOne = useCallback(async (env: EnvelopeV1) => {
    setBusy(env.delivery_id); setError(null);
    try {
      const insight = await decryptEnvelope(env);
      setInsights((prev) => ({ ...prev, [env.delivery_id]: insight }));
    } catch (e) { setError(friendly(e)); } finally { setBusy(null); }
  }, []);

  const decryptAll = useCallback(async () => {
    for (const env of items) {
      if (insights[env.delivery_id]) continue;
      try {
        const insight = await decryptEnvelope(env);
        setInsights((prev) => ({ ...prev, [env.delivery_id]: insight }));
      } catch (e) { setError(friendly(e)); break; }
    }
  }, [items, insights]);

  return (
    <>
      <header className="hero">
        <h1>Subscriber <em>insights</em></h1>
        <p>
          Owner-authorized AI summaries, encrypted for your wallet only. Decryption happens
          here in your browser — the gateway only ever sends ciphertext. Five fields, nothing more.
        </p>
      </header>

      <div className="warn-strip">
        Demo safety: your private key lives in this tab&apos;s memory only — never in
        <code> localStorage</code>. Closing or logging out forgets it. Raw sensor readings
        (temperature, vibration, RPM) are never available on this screen.
      </div>

      {/* 1 — wallet login */}
      <section className="card">
        <h2><span className="step">1</span> Wallet login</h2>
        <p className="sub">EIP-191 challenge signed by your wallet. Session is an HttpOnly cookie.</p>
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

      {/* 2 — key enrollment */}
      <section className="card">
        <h2><span className="step">2</span> Encryption key {hasKey && <span className="pill ok">ENROLLED</span>}</h2>
        <p className="sub">
          Your X25519 public key, bound to your wallet. Rotation invalidates unread envelopes.
          32 bytes, standard base64. Private key never leaves this tab&apos;s memory.
        </p>
        {hasKey ? (
          <p className="mono">{pubB64}</p>
        ) : (
          <>
            <div className="row">
              <button onClick={enrollFresh} disabled={!wallet || busy === "enroll"}>
                {busy === "enroll" ? "Enrolling…" : "Generate + enroll new key"}
              </button>
            </div>
            <div className="row" style={{ marginTop: 10 }}>
              <input
                type="text"
                placeholder="Or paste existing 32-byte base64 private key"
                value={importB64}
                onChange={(e) => setImportB64(e.target.value)}
                aria-label="Existing private key"
              />
              <button className="ghost" onClick={importExisting} disabled={!wallet || !importB64.trim() || busy === "import"}>
                Import for this session
              </button>
            </div>
          </>
        )}
      </section>

      {/* 3 — envelopes */}
      <section className="card">
        <h2><span className="step">3</span> Encrypted envelopes</h2>
        <p className="sub">Polled every 15s from <code className="mono">GET /v1/insights</code>. Authorization re-checked on every read.</p>
        <div className="row" style={{ marginBottom: 12 }}>
          <input
            type="text"
            value={resourceId}
            onChange={(e) => setResourceId(e.target.value)}
            aria-label="Resource ID"
            spellCheck={false}
          />
          <button className="ghost" onClick={() => fetchPage(null, false)} disabled={!wallet || busy === "fetch"}>
            Refresh
          </button>
          <button className="ghost" onClick={decryptAll} disabled={!hasKey || items.length === 0}>
            Decrypt all
          </button>
        </div>

        {!wallet && <p className="muted">Log in to request envelopes.</p>}
        {wallet && items.length === 0 && busy !== "fetch" && (
          <p className="muted">No envelopes — grant may be pending, revoked, or no anomalies yet.</p>
        )}

        {items.map((env) => {
          const ins = insights[env.delivery_id];
          return (
            <article className="env" key={env.delivery_id}>
              <div className="env-head">
                <span className="mono">{env.delivery_id.slice(0, 8)}…</span>
                <span className="pill">epoch {env.key_epoch}</span>
                <span className="pill">policy v{env.policy_version}</span>
                {ins ? (
                  <span className={`pill ${ins.severity.toLowerCase()}`}>{ins.severity}</span>
                ) : (
                  <button className="ghost" onClick={() => decryptOne(env)} disabled={!hasKey || busy === env.delivery_id}>
                    {busy === env.delivery_id ? "Decrypting…" : hasKey ? "Decrypt" : "Enroll key first"}
                  </button>
                )}
              </div>
              {ins ? (
                <dl className="insight">
                  <div className="field"><dt>event_id</dt><dd>{ins.event_id}</dd></div>
                  <div className="field"><dt>event_type</dt><dd>{ins.event_type}</dd></div>
                  <div className="field"><dt>severity</dt><dd>{ins.severity}</dd></div>
                  <div className="field"><dt>observed_at</dt><dd>{ins.observed_at}</dd></div>
                  <div className="field"><dt>model_version</dt><dd>{ins.model_version}</dd></div>
                </dl>
              ) : (
                <p className="mono">ciphertext: {env.ciphertext_b64.slice(0, 44)}… (not readable without your key)</p>
              )}
            </article>
          );
        })}

        {cursor && !done && (
          <div className="row" style={{ marginTop: 12 }}>
            <button className="ghost" onClick={() => fetchPage(cursor, true)} disabled={busy === "fetch"}>
              Load more
            </button>
          </div>
        )}
      </section>

      {error && <div className="err" role="alert"><code>!</code> {error}</div>}

      <footer className="foot">
        Shows only <code>event_id, event_type, severity, observed_at, model_version</code> after
        local decrypt + AAD check. Revocation stops <em>future</em> deliveries — anything already
        decrypted cannot be un-seen.
      </footer>
    </>
  );
}
