"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export function AppIcon({ kind }: { kind: "back" | "network" | "devices" | "insights" | "shield" }) {
  const paths = {
    back: "M19 12H5m6-6-6 6 6 6",
    network: "M5 12h7m0 0V5h7m-7 7v7h7M2 9h6v6H2zM17 2h5v6h-5zM17 16h5v6h-5z",
    devices: "M3 5h18v14H3zM7 9h10m-10 4h5M7 19v3m10-3v3",
    insights: "M4 3h12l4 4v14H4zM8 11h8m-8 4h6M15 3v5h5",
    shield: "m12 2 9 4v6c0 5-9 10-9 10S3 17 3 12V6zM8 12l3 3 5-6",
  };
  return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[kind]} /></svg>;
}

export default function ClientShell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  if (path === "/") return <main className="shell">{children}</main>;
  const nav = [
    { href: "/", title: "Network overview", icon: "network" as const },
    { href: "/dashboard", title: "My devices", icon: "devices" as const },
    { href: "/insights", title: "Shared insights", icon: "insights" as const },
  ];
  const title = nav.find(item => item.href === path)?.title ?? (path === "/login" ? "Sign in" : "Technical reference");
  return <div className="client-app">
    <a className="client-skip" href="#page-content">Skip to content</a>
    <aside className="client-sidebar">
      <Link className="client-brand" href="/"><AppIcon kind="shield" /><span>PrivacyGate <small>AI</small></span></Link>
      <div className="client-workspace-label">Your workspace<span>Local v2 research demo</span></div>
      <nav aria-label="Main navigation">{nav.map(item => <Link key={item.href} href={item.href} aria-current={path === item.href ? "page" : undefined}><AppIcon kind={item.icon} />{item.title}</Link>)}</nav>
      <div className="client-sidebar-foot"><AppIcon kind="shield" /><strong>Share with confidence.</strong><p>You decide who can receive insights from your equipment.</p><Link href="/api-docs">Technical reference</Link></div>
    </aside>
    <div className="client-body"><header className="client-topbar"><Link className="back-link" href="/"><AppIcon kind="back" />Back to network</Link><span>{title}</span></header><main id="page-content" tabIndex={-1} className="client-content">{children}</main><footer className="client-global-foot">PrivacyGate AI · Local research demo <Link href="/">Network overview</Link></footer></div>
  </div>;
}
