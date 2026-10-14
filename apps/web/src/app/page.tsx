import Link from "next/link";

export default function Home() {
  return (
    <>
      <header className="hero">
        <h1>PrivacyGate <em>AI</em></h1>
        <p>
          Local demo: owner detail view vs encrypted third-party insight, gated by a
          confirmed on-chain grant. Gateway defaults to http://127.0.0.1:8000
          (override with NEXT_PUBLIC_GATEWAY_URL).
        </p>
      </header>
      <section className="card">
        <h2><span className="step">→</span> Start</h2>
        <div className="row">
          <Link href="/dashboard"><button>Owner dashboard</button></Link>
          <Link href="/insights"><button className="ghost">Subscriber insights</button></Link>
        </div>
      </section>
    </>
  );
}
