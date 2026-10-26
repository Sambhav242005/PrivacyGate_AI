const routes=[
 ["POST","/v2/auth/login","Public","Username/password; creates HttpOnly session and CSRF token."],
 ["GET","/v2/me","Session","Restore current account and stable CSRF token."],
 ["POST","/v2/auth/logout","Session + CSRF","Delete current session."],
 ["GET","/v2/accounts","Owner","Provisioned demo accounts for owner invitations."],
 ["GET · POST","/v2/devices","Owner · POST requires CSRF","List owned devices or register one by name."],
 ["GET","/v2/resources/{resource_id}/telemetry","Owner","Private detailed readings; cursor pagination."],
 ["POST","/v2/simulator","Owner + CSRF","Bounded signed-sensor simulation; normal, anomaly, tampered, replayed, stale, malformed, or wrong-device."],
 ["GET · POST","/v2/keys","Session · POST requires CSRF","Read own enrollment or register an X25519 public key."],
 ["GET · POST","/v2/policies","Owner · POST requires CSRF","List policies or grant fixed READ_INSIGHT scope to a reader."],
 ["POST","/v2/policies/{policy_id}/revoke","Owner + CSRF","Revoke future delivery and return a confirmed receipt."],
 ["GET","/v2/operations/{transaction_id}","Session","Inspect own pending or committed operation."],
 ["GET","/v2/insights","Reader","List recipient-encrypted EnvelopeV2 deliveries."],
 ["GET","/v2/audit","Owner","Permission transaction receipts."],
 ["GET","/v2/health · /v2/ready","Public","Liveness and component readiness."],
];
export default function ApiDocs(){return <><header className="hero"><h1>Gateway reference</h1><p>Approved local v2 routes for the owner and reader workspaces.</p></header><section className="card"><p className="sub">Mutations require the session CSRF token. Authorization is enforced by the gateway on every protected publication and retrieval.</p><div className="table-scroll"><table><caption>PrivacyGate gateway · /v2</caption><thead><tr><th>Method</th><th>Route</th><th>Access</th><th>Purpose</th></tr></thead><tbody>{routes.map(([method,path,access,purpose])=><tr key={`${method}-${path}`}><td><span className="pill">{method}</span></td><td><code>{path}</code></td><td>{access}</td><td>{purpose}</td></tr>)}</tbody></table></div><h2>EnvelopeV2</h2><p className="muted">Reader responses contain only the exact v2 encrypted envelope fields. The browser verifies schema, account, resource, canonical authenticated metadata, and AES-GCM tag before showing the fixed insight payload.</p><pre className="mono">{`{ schema_version, delivery_id, resource_id, recipient_id, policy_version, key_version, key_epoch, ephemeral_public_key_b64, nonce_b64, aad_b64, ciphertext_b64 }`}</pre><h2>Privacy boundary</h2><p className="muted">Detailed telemetry is returned only by the owner endpoint. Reader routes never return raw telemetry, decrypted insights, device signing keys, or reader private keys.</p></section></>}
