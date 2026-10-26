> **v2 supersession (2026-10-26):** The approved native custom-blockchain design in [V2.md](V2.md) governs new implementation. EVM/wallet/MQTT and incompatible v1 tooling/schema requirements below are historical. Completion requires dated v2 evidence, not the legacy checkboxes.

# MISTAKES.md — Pitfalls, Anti-Patterns and Lessons Log

> **Important:** These are *anticipated risks*, not assertions that project contributors made these mistakes. Add real incidents after reproducing them, with dates, fixes and regression tests.

## Preemptive pitfalls

| ID | Mistake to avoid | Why it's harmful | Prevention and regression test |
|---|---|---|---|
| M-01 | Store sensor packets on blockchain | Cost, permanent leakage, slow writes | T-18 inspect chain calldata and events |
| M-02 | Assume blockchain enforces decryption | Authorization entry doesn't stop anyone with old key/plaintext | T-13, T-19 require gateway denial and fresh recipient envelopes |
| M-03 | Let AI choose permitted fields | Prompt/model output could leak confidential readings | T-06 exact five-key serialization, unknown fields forbidden |
| M-04 | Grant access on submitted tx hash | Pending, reverted or forged tx hashes can bypass policy | T-07, T-12 validate contract current state + confirmed receipt |
| M-05 | Share a single symmetric key among readers | Revoked reader could decrypt future streams | T-09, T-13, T-19 per-recipient ECDH envelopes |
| M-06 | Ignore MQTT QoS 1 duplicates | Retries inflate anomaly counts and break history | T-03 atomic last-sequence + unique DB constraint |
| M-07 | Treat signed packet as trusted measurement | Signatures prove key use, not real-world sensor accuracy | Threat model + synthetic-only validation |
| M-08 | Store decrypted telemetry in logs or DB metadata | Bypasses otherwise encrypted storage | T-18 generated canary strings + DB/log scan |
| M-09 | Check permissions only in browser | Direct API calls leak raw data | T-10, T-15 server-side IDOR and scope tests |
| M-10 | Continue sharing while chain RPC is offline | Stale authorization may have been revoked | T-14 fail closed on release/read |
| M-11 | Claim immediate revocation at tx submission | Block confirmation/sync takes time; old plaintext persists | T-12 and T-13 clear `PENDING/CONFIRMED/SYNCED` states |
| M-12 | Call anomaly score a calibrated confidence | Model score often isn't a probability | T-23 metrics, threshold and severity calibration docs |
| M-13 | Hash different policy JSON encodings across JS/Python | Valid grant appears invalid, or duplicate representations slip through | Shared golden canonical fixtures and digest cross-test |
| M-14 | Use local Anvil as evidence of decentralization | One process creates/manages all blocks | State lab-chain limitation in demo and report |
| M-15 | Copy development private keys into frontend repository | Secrets leak to users, git and screenshots | Secret scan + `.gitignore`; empty example values |
| M-16 | Store recipient private key in localStorage | XSS/browser extension can steal it | Client memory or secure user-controlled wallet/keystore; frontend tests |
| M-17 | Equate encrypted SQLite columns with whole-DB encryption | Metadata remains visible | Accurate wording and DB inspection |
| M-18 | Infer policy validity from local policy state alone | Owner may have revoked on chain | Check exact digest/version/expiry and current on-chain grant at every output/read |
| M-19 | Retry decryption with alternate contexts on error | Can introduce downgrade/confusion risks | Explicit schema version + authenticated AAD + fail hard |
| M-20 | Claim zero disclosure because fields were removed | Alert time/frequency can still imply activity | Describe residual metadata leakage; restrict cadence and retention |
| M-21 | Treat generated synopsis goals as tested features | Creates false academic evidence | Distinguish requirements vs measured results everywhere |
| M-22 | Overbuild payment, marketplace and ZK proofs first | Blocks achievable MVP | Follow `TASKS.md` milestones and scope gate |

## Triage checklist for real incidents

1. **Reproduce:** smallest failing input and expected vs actual behavior.
2. **Classify:** security/privacy, correctness, integration, performance or documentation.
3. **Contain:** disable third-party delivery if unauthorized disclosure is possible.
4. **Fix:** correct root cause, not just surface symptom; use focused code changes.
5. **Prevent:** add failing-then-passing test and update related spec/decision.
6. **Measure:** include actual test command/results; never label untested as fixed.

## Incident entry template

```markdown
### YYYY-MM-DD — INC-001 — Short description
- **Status:** Open | Mitigated | Resolved
- **Component / task:** path and TASK-ID
- **Observed failure:** exact conditions and user-visible impact
- **Root cause:** verified explanation, not a guess
- **Privacy/security impact:** affected permissions/data
- **Fix:** commit/PR or file changes
- **Regression test:** path, command and result
- **Follow-up:** remaining risk and owner
```

## Confirmed incidents

### 2026-10-26 — INC-V2-001 — Windows CI service lifecycle and timestamp types

- **Status:** Fix implemented; the Actions run attached to the fix is the remote verification gate.
- **Observed:** Run 40363579050 passed backend/build checks and startup, then browser navigation failed with ERR_CONNECTION_REFUSED in the next shell step. Run 40364790801 passed the browser journey after combining the lifecycle, then cleanup incorrectly reported a reused PID.
- **Cause:** Background services did not survive the separate Windows startup shell. PowerShell 7 also deserializes the recorded ISO timestamp as DateTime, unlike the string representation used by Windows PowerShell 5; comparing its formatted representation to a string falsely rejected the correct process.
- **Fix:** Keep startup, Playwright and finally cleanup in one run step. Compare process-start instants as UTC ticks through ProcessIdentity.ps1; retain fail-closed handling for mismatched or malformed process records.
- **Regression:** tests/v2/test_process_identity.py checks actual process metadata using string, DateTime and offset representations; a one-tick mismatch and malformed record must be rejected. Local regression passed. The required live Actions journey remains the cross-step lifecycle regression.
- **References:** https://github.com/Sambhav242005/PrivacyGate_AI/actions/runs/40363579050 and https://github.com/Sambhav242005/PrivacyGate_AI/actions/runs/40364790801.

## Known open design risks (not incidents)

- The trusted local gateway can access all raw telemetry in memory; compromise bypasses intended privacy.
- A narrow event may still reveal an operational schedule through timestamps or frequency.
- Local chain is centralized; its events provide **demonstration receipts**, not independently operated consensus.
- Owner wallet loss and transfer are out of MVP; simulate with disposable test wallets.
- A local CPU anomaly model trained on synthetic data cannot establish field accuracy.
- The current design blocks queued unread envelopes on revocation; anything already obtained cannot be revoked.
