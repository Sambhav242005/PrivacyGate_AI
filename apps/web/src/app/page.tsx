"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import styles from "./network.module.css";

type NodeId = "sensor" | "gateway" | "owner" | "reader" | "chain";
type Scenario = "allowed" | "revoked" | "outage";
type IconName = NodeId | "map" | "arrow" | "play" | "pause" | "reset" | "shield";

function Icon({ name, size = 20 }: { name: IconName; size?: number }) {
  const paths: Record<IconName, React.ReactNode> = {
    sensor: <><rect x="7" y="7" width="10" height="10" rx="2" /><path d="M10 1v3m4-3v3M10 20v3m4-3v3M1 10h3m-3 4h3m16-4h3m-3 4h3M10 10h4v4h-4z" /></>,
    gateway: <><rect x="3" y="3" width="18" height="7" rx="2" /><rect x="3" y="14" width="18" height="7" rx="2" /><path d="M7 6.5h.01M7 17.5h.01M12 6.5h5M12 17.5h5" /></>,
    owner: <><rect x="2" y="5" width="20" height="15" rx="3" /><path d="M2 9h20m-6 4h6m-5 3h.01M6 5V3h12v2" /></>,
    reader: <><path d="M2 6h8l2 2h10v13H2zM9 14h6m-6 3h4M5 3h10l2 2" /></>,
    chain: <path d="m12 2 9 5v10l-9 5-9-5V7zM3 7l9 5 9-5M12 12v10" />,
    map: <><circle cx="5" cy="12" r="3" /><circle cx="19" cy="5" r="3" /><circle cx="19" cy="19" r="3" /><path d="m8 11 8-5M8 13l8 5" /></>,
    arrow: <path d="M4 12h16m-6-6 6 6-6 6" />,
    play: <path d="m8 4 12 8-12 8z" />,
    pause: <path d="M8 4v16M16 4v16" />,
    reset: <path d="M3 11a9 9 0 1 1 2 7M3 4v7h7" />,
    shield: <><path d="m12 2 9 4v6c0 5-9 10-9 10S3 17 3 12V6z" /><path d="m8 12 3 3 5-6" /></>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}

const nodes: Record<NodeId, { name: string; role: string; description: string; sends: string; receives: string; chain: string; href: string; action: string }> = {
  sensor: { name: "Compressor A", role: "IoT sensor", description: "The starting point. Signs each sensor packet before sending it to the local gateway through the simulator transport.", sends: "Signed sensor packets to the gateway", receives: "No reader data", chain: "No direct connection. Sensor readings stay off-chain.", href: "/dashboard", action: "Manage devices" },
  gateway: { name: "AI gateway", role: "Local processing", description: "Verifies the device, stores encrypted readings, and produces a limited insight. Checks permission before sending or serving an envelope.", sends: "Owner detail or recipient-encrypted insight", receives: "Signed packets and confirmed permission state", chain: "Reads the current grant. Uncertain authorization blocks third-party delivery.", href: "/dashboard", action: "View my devices" },
  owner: { name: "Device owner", role: "Controls access", description: "The owner can review detailed telemetry and authorize a specific reader through their password-protected account. The gateway enforces access.", sends: "Register, grant, and revoke transactions", receives: "Detailed readings from the gateway", chain: "The trusted gateway signs permission transactions for the owner account.", href: "/dashboard", action: "My devices" },
  reader: { name: "Maintenance partner", role: "Insight reader", description: "Receives only an owner-authorized encrypted insight. The intended recipient decrypts it in their own browser.", sends: "Authenticated requests to the gateway", receives: "Encrypted insights, never raw readings", chain: "The gateway reads permissions on the reader’s behalf; insights are fetched from the gateway.", href: "/insights", action: "Shared insights" },
  chain: { name: "Permission registry", role: "Custom local chain", description: "A single local validator records ownership and permission state. The gateway checks confirmed state before any reader delivery.", sends: "Confirmed ownership and grant state", receives: "Account IDs, scope, expiry, and policy digest", chain: "Authorization lives here. Telemetry and insight content do not.", href: "/dashboard", action: "Manage permissions" },
};

const steps = [
  { title: "Ready to follow a packet", detail: "Run the walkthrough to see how the components work together.", node: "sensor" as NodeId },
  { title: "Sensor sends a signed packet", detail: "Compressor A sends a signed packet to the gateway over the local simulator transport. Nothing is written to the chain.", node: "sensor" as NodeId },
  { title: "Gateway verifies and processes", detail: "The gateway verifies the signature, encrypts the stored reading, and prepares a limited insight.", node: "gateway" as NodeId },
  { title: "Gateway reads the permission", detail: "The permission registry supplies confirmed grant state. The gateway checks the owner’s approved policy.", node: "chain" as NodeId },
  { title: "Encrypted insight delivered", detail: "Only the permitted reader receives an envelope. Detailed readings remain in the owner’s view.", node: "reader" as NodeId },
];

const mobileConnections: Record<NodeId, string> = {
  sensor: "Sends signed packets to the gateway",
  gateway: "Reads chain permission; sends to owner or reader",
  owner: "Requests grants and revocations through the gateway",
  reader: "Receives encrypted insights from the gateway",
  chain: "Returns permission state to the gateway",
};

export default function Home() {
  const [selected, setSelected] = useState<NodeId>("gateway");
  const [scenario, setScenario] = useState<Scenario>("allowed");
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const blocked = scenario !== "allowed";
  const current = nodes[selected];

  const advanceStep = useCallback(() => {
    const nextStep = Math.min(step + 1, 4);
    setStep(nextStep);
    setSelected(steps[nextStep].node);
    if (nextStep === 4) setPlaying(false);
  }, [step]);

  useEffect(() => {
    if (!playing) return;
    const timer = window.setInterval(advanceStep, 1800);
    return () => window.clearInterval(timer);
  }, [playing, advanceStep]);

  function chooseScenario(value: Scenario) {
    setScenario(value); setStep(0); setPlaying(false);
    setSelected(value === "allowed" ? "gateway" : "chain");
  }

  function status(id: NodeId) {
    if (!step) return "Demo component";
    if (id === "sensor") return "Packet sent";
    if (id === "gateway") return step >= 2 ? "Packet verified" : "Awaiting packet";
    if (id === "owner") return "Detail access";
    if (id === "chain") return step < 3 ? "Awaiting check" : scenario === "outage" ? "Unreachable" : scenario === "revoked" ? "Revocation synced" : "Grant confirmed";
    return step < 4 ? "Awaiting insight" : blocked ? "Delivery blocked" : "Insight received";
  }

  const eventTitle = (index: number) => index === 4 && blocked ? "Third-party delivery blocked" : index === 3 && scenario === "outage" ? "Permission check unavailable" : index === 3 && scenario === "revoked" ? "Confirmed revocation observed" : steps[index].title;
  const eventDetail = step === 3 && scenario === "outage"
    ? "The chain cannot be reached. No current permission can be confirmed, so the gateway must deny third-party delivery."
    : step === 3 && scenario === "revoked"
      ? "The gateway observes a confirmed, synced revocation. This reader no longer has permission to receive new or unread deliveries."
      : step === 4 && blocked
        ? scenario === "outage"
          ? "The chain cannot be reached. Authorization is unknown, so no new or unread envelope is released."
          : "The confirmed revocation has been synced. New and unread deliveries are denied; previously decrypted content cannot be recalled."
        : steps[step].detail;

  return (
    <div className={styles.workspace}>
      <a className={styles.skip} href="#network-content">Skip to network</a>
      <aside className={styles.sidebar} aria-label="Workspace navigation">
        <Link className={styles.brand} href="/" aria-label="PrivacyGate AI home"><span className={styles.brandIcon}><Icon name="shield" size={23} /></span>PrivacyGate<span className={styles.ai}>AI</span></Link>
        <div className={styles.workspaceName}><span className={styles.workspaceAvatar}>P</span><div>Research workspace<small>Local academic demo</small></div></div>
        <nav><Link className={styles.activeNav} href="/" aria-current="page"><Icon name="map" />Network overview</Link><Link href="/dashboard"><Icon name="owner" />My devices</Link><Link href="/insights"><Icon name="reader" />Shared insights</Link></nav>
        <div className={styles.sidebarBottom}><Icon name="shield" /><strong>Your data. Your permissions.</strong><p>Share the insight. Keep control of the readings.</p><Link href="/login">Sign in <Icon name="arrow" size={16} /></Link></div>
      </aside>
      <div className={styles.main} id="network-content">
        <header className={styles.topbar}><span>Workspace <span className={styles.slash}>/</span> <strong>Network overview</strong></span><Link href="/login"><Icon name="owner" size={17} /> Sign in</Link></header>
        <div className={styles.content}>
          <div className={styles.pageHeading}><div><h1>Your network, at a glance.</h1><p>See where data moves, who controls access, and who receives an insight.</p></div><span className={styles.demoBadge}><span />Illustrative demo</span></div>
          <div className={styles.demoNotice}><Icon name="map" size={18} /><p>This is an interactive walkthrough. Connections and activity below are illustrative; this map does not report live service health.</p></div>
          <section className={styles.networkSection} aria-labelledby="network-title">
            <div className={styles.sectionHeading}><div><h2 id="network-title">Network map</h2><p>Select a component to explore its connections.</p></div><div className={styles.legend}><span><i className={styles.dataKey} />Data</span><span><i className={styles.readKey} />Permission read</span><span><i className={styles.writeKey} />Permission update</span></div></div>
            <div className={styles.mapLayout}>
              <div className={styles.map} aria-label="Sensor sends to gateway. Owner receives details and writes permissions to the chain. Gateway reads the chain and sends encrypted insights to the reader.">
              <div className={styles.mapCaption}>OFF-CHAIN DATA · CUSTOM LOCAL CHAIN PERMISSIONS</div>
                <svg className={styles.connections} viewBox="0 0 1000 540" preserveAspectRatio="none" aria-hidden="true">
                  <defs><marker id="data-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="m0 0 7 3.5L0 7" fill="#438777" /></marker><marker id="read-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="m0 0 7 3.5L0 7" fill="#7662b0" /></marker><marker id="write-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="m0 0 7 3.5L0 7" fill="#b7813b" /></marker></defs>
                  <path className={step >= 1 ? styles.flowActive : ""} d="M255 213H370" stroke="#438777" markerEnd="url(#data-arrow)" />
                  <path d="M590 213H648V98H735" stroke="#438777" markerEnd="url(#data-arrow)" />
                  <path className={step >= 4 && !blocked ? styles.flowActive : ""} d="M590 213H648V323H735" stroke={step >= 4 && blocked ? "#b55145" : "#438777"} markerEnd={step >= 4 && blocked ? undefined : "url(#data-arrow)"} />
                  <path className={step >= 3 && scenario !== "outage" ? styles.flowActive : ""} d="M480 376V269" stroke="#7662b0" strokeDasharray="5 5" markerEnd="url(#read-arrow)" />
                  <path d="M845 154V185H975V505H650V433H590" stroke="#b7813b" strokeDasharray="5 5" markerEnd="url(#write-arrow)" />
                </svg>
                <span className={`${styles.edgeLabel} ${styles.sensorEdge}`}>Signed packets</span><span className={`${styles.edgeLabel} ${styles.ownerEdge}`}>Detailed readings</span><span className={`${styles.edgeLabel} ${styles.readerEdge}`}>{step === 4 && blocked ? "Delivery blocked" : "Encrypted insight"}</span><span className={`${styles.edgeLabel} ${styles.readEdge}`}>Read permission</span><span className={`${styles.edgeLabel} ${styles.writeEdge}`}>Write grant / revoke</span>
                {(["sensor", "gateway", "chain", "owner", "reader"] as NodeId[]).map(id => <button key={id} className={`${styles.node} ${styles[id]} ${selected === id ? styles.selectedNode : ""}`} onClick={() => setSelected(id)} aria-pressed={selected === id} aria-label={`Inspect ${nodes[id].name}`}><span className={styles.nodeIcon}><Icon name={id} size={24} /></span><span className={styles.nodeText}><small>{nodes[id].role}</small><strong>{nodes[id].name}</strong></span><span className={styles.mobileConnection}>{mobileConnections[id]}</span><span className={`${styles.nodeStatus} ${((id === "reader" && step === 4 && blocked) || (id === "chain" && scenario !== "allowed" && step >= 3)) ? styles.blockedStatus : ""}`}><i />{status(id)}</span></button>)}
                <div className={styles.mapFootnote}><Icon name="shield" size={14} />Telemetry and insight content stay off-chain.</div>
              </div>
              <aside className={styles.inspector} aria-labelledby="component-title"><div className={styles.inspectorIcon}><Icon name={selected} size={26} /></div><h3 id="component-title">{current.name}</h3><span className={styles.componentRole}>{current.role}</span><p>{current.description}</p><dl><div><dt>Sends</dt><dd>{current.sends}</dd></div><div><dt>Receives</dt><dd>{current.receives}</dd></div><div><dt>Permission registry</dt><dd>{current.chain}</dd></div></dl><Link className={styles.detailLink} href={current.href}>{current.action}<Icon name="arrow" size={16} /></Link></aside>
            </div>
          </section>
          <section className={styles.walkthrough} aria-labelledby="walkthrough-title">
            <div className={styles.walkthroughHeader}><div><h2 id="walkthrough-title">Follow a packet</h2><p>A guided demo of the data and permission flow.</p></div><div className={styles.scenarios} role="group" aria-label="Demo scenario"><button aria-pressed={scenario === "allowed"} onClick={() => chooseScenario("allowed")}>Access allowed</button><button aria-pressed={scenario === "revoked"} onClick={() => chooseScenario("revoked")}>After revocation</button><button aria-pressed={scenario === "outage"} onClick={() => chooseScenario("outage")}>Chain offline</button></div></div>
            <div className={styles.playback}><div className={styles.playbackCopy} aria-live="polite"><strong>{eventTitle(step)}</strong><p>{eventDetail}</p></div><div className={styles.playbackControls}><button className={styles.primaryButton} onClick={() => { if (step === 4) setStep(0); setPlaying(value => !value); }}><Icon name={playing ? "pause" : "play"} size={16} />{playing ? "Pause" : step === 4 ? "Replay demo" : "Run walkthrough"}</button><button className={styles.secondaryButton} disabled={playing || step === 4} onClick={advanceStep}>Next step<Icon name="arrow" size={16} /></button><button className={styles.iconButton} aria-label="Reset walkthrough" onClick={() => { setStep(0); setPlaying(false); setSelected("gateway"); }}><Icon name="reset" size={17} /></button></div></div>
            <ol className={styles.stepTrack} aria-label="Packet progress">{["Signed packet", "Local processing", "Permission check", blocked ? "Blocked delivery" : "Encrypted delivery"].map((label, i) => <li key={label} className={step > i ? styles.completedStep : ""}><span>{i + 1}</span>{label}</li>)}</ol>
          </section>
          <div className={styles.bottomGrid}><section className={styles.activity} aria-labelledby="activity-title"><div className={styles.activityHeading}><h2 id="activity-title">Activity feed</h2><span>Demo events</span></div>{step === 0 ? <div className={styles.emptyActivity}><Icon name="map" /><p>No packets in this walkthrough yet.<span>Run the demo or take it one step at a time.</span></p></div> : <ol>{Array.from({ length: step }, (_, i) => step - i).map(index => <li key={index}><span className={styles.eventNumber}>{index}</span><div><strong>{eventTitle(index)}</strong><span>{nodes[steps[index].node].name}</span></div><span className={styles.eventKind}>{index === 3 ? "Chain read" : index === 4 && blocked ? "Blocked" : "Off-chain"}</span></li>)}</ol>}</section><section className={styles.accessSummary}><Icon name="shield" size={22} /><h2>Two views. One clear boundary.</h2><div><strong>Device owner</strong><span>Detailed telemetry · controls permissions</span></div><div><strong>Authorized reader</strong><span>Encrypted insights · five approved fields</span></div><p>The chain records who may read. The gateway checks permission and delivers the data.</p></section></div>
          <footer className={styles.footer}><span>PrivacyGate AI · Research workspace</span><span>Demo only · No live transactions are sent</span></footer>
        </div>
      </div>
    </div>
  );
}
