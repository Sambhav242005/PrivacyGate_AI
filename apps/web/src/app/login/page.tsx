"use client";

import { useState } from "react";
import Link from "next/link";
import { ApiError, api } from "@/lib/api";
import { hasInjectedWallet, loginWithWallet } from "@/lib/wallet";

export default function LoginPage() {
  const [wallet, setWallet] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function login() {
    setErr(null);
    setInfo(null);
    setBusy(true);
    try {
      if (!hasInjectedWallet()) throw new Error("No browser wallet detected.");
      const addr = await loginWithWallet(api);
      setWallet(addr);
      setInfo(`Signed in as ${addr}. Session is a cookie, not localStorage.`);
    } catch (e) {
      setErr(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function logout() {
    try {
      await api.logout();
    } catch {
      /* already gone */
    }
    setWallet(null);
    setInfo("Signed out.");
  }

  return (
    <>
      <header className="hero">
        <h1>Owner <em>login</em></h1>
        <p>Wallet challenge (EIP-191). The server sets an HttpOnly session cookie.</p>
      </header>
      <section className="card">
        <h2><span className="step">1</span> Connect + sign</h2>
        {wallet ? (
          <div className="row">
            <span className="pill ok">CONNECTED</span>
            <span className="addr">{wallet}</span>
            <button className="ghost" onClick={logout}>Sign out</button>
          </div>
        ) : (
          <button onClick={login} disabled={busy}>{busy ? "Waiting for signature…" : "Connect wallet and sign in"}</button>
        )}
        {info && <p className="muted">{info}</p>}
        {err && <div className="err" role="alert"><code>!</code> {err}</div>}
        <p className="muted"><Link href="/(owner)/dashboard">Continue to owner dashboard →</Link></p>
      </section>
    </>
  );
}
