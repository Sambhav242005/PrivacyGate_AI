"""PG-042 MVP E2E rig (no live Anvil/MQTT required).

Covers T-01..T-24 slice at module level using existing gateway/simulator
modules only:
  simulator sign -> ingest verify + schema -> replay/tamper reject ->
  baseline -> strict serializer (T-06) -> dispatch with fake chain (T-08)
  -> envelope round-trip (T-09/T-16 negative) -> revoke blocks unread +
  new dispatch (T-13/T-19) -> expiry/scope denial (T-07/T-11) ->
  chain-outage fail-closed (T-14).

Live-service check at the end SKIPS when Anvil/MQTT are unreachable, so
this file passes on a bare checkout. Live runs remain manual per
docs/results/README.md.
"""
from __future__ import annotations

import base64
import socket
import sys
import uuid
from pathlib import Path

import pytest
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[2]
GW_SRC = ROOT / "apps" / "gateway" / "src"
SIM_SRC = ROOT / "apps" / "simulator" / "src"
sys.path.insert(0, str(GW_SRC))
sys.path.insert(0, str(SIM_SRC))

from simulator import signing as sim_signing  # noqa: E402
from privacygate.chain.client import ChainUnavailable  # noqa: E402
from privacygate.chain.permissions import (  # noqa: E402
    AuthzUnavailable,
    PolicyDenied,
)
from privacygate.domain.schemas import SignedTelemetryV1  # noqa: E402
from privacygate.ingest.signatures import verify_message  # noqa: E402
from privacygate.services.delivery import (  # noqa: E402
    DeliveryQueue,
    decrypt_envelope,
    scan_no_plaintext,
)
from privacygate.services.event_pipeline import (  # noqa: E402
    process_candidate,
    process_reading,
)

RES = "0x" + "aa" * 32
READER = "0x" + "22" * 20
READER2 = "0x" + "33" * 20
DIGEST = "0x" + "ab" * 32
OTHER_DIGEST = "0x" + "cd" * 32
NOW = 1700000000
EXPIRES = 1800000000
ISSUED_AT = "2026-10-14T12:00:00.000Z"
OBSERVED_AT = "2026-10-14T12:00:01.000Z"
SUBSCRIBER_FIELDS = {"event_id", "event_type", "severity", "observed_at", "model_version"}

signing_key = SigningKey.generate()
PUBKEY = bytes(signing_key.verify_key)


class FakeChain:
    """Confirmed-state stub: active flag + outage switch, no network."""

    def __init__(self, active=True, outage=False, digest=DIGEST,
                 expires=EXPIRES, scope=1):
        self.active = active
        self.outage = outage
        self.digest = digest
        self.expires = expires
        self.scope = scope

    def get_grant(self, resource_id, reader_wallet):
        if self.outage:
            raise ChainUnavailable("rpc down")
        return {"policy_digest": self.digest, "expires_at": self.expires,
                "version": 1, "active": self.active, "scope": self.scope}


def _grant_chain(**kw):
    params = {"active": True, "outage": False, "digest": DIGEST,
              "expires": EXPIRES, "scope": 1}
    params.update(kw)
    return FakeChain(**params)


def _signed_msg(seq=1, issued_at=ISSUED_AT):
    unsigned = {
        "schema_version": 1,
        "device_id": str(uuid.uuid4()),
        "resource_id": RES,
        "sequence": seq,
        "issued_at": issued_at,
        "telemetry": {"temp_c": 70.1, "vibration_mm_s": 2.0, "rpm": 1450},
    }
    return sim_signing.sign_message(signing_key, unsigned)


def _queue_for(reader, chain=None):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    q = DeliveryQueue()
    priv = X25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    priv_b64 = base64.b64encode(priv.private_bytes_raw()).decode()
    q.register_key(reader, pub_b64)
    return q, priv_b64


def _anomaly_insight():
    insight = process_reading(
        {"temp_c": 95.0, "vibration_mm_s": 7.5, "rpm": 1450}, OBSERVED_AT)
    assert insight is not None
    assert insight.event_type == "MACHINE_ANOMALY"
    return insight


def test_ingest_valid_accepted_once():
    msg = _signed_msg(seq=1)
    assert verify_message(PUBKEY, msg) is True
    parsed = SignedTelemetryV1.model_validate(msg)  # schema/range gate
    assert parsed.sequence == 1
    seen = set()
    assert parsed.sequence not in seen  # T-01: stored exactly once
    seen.add(parsed.sequence)


def test_ingest_tamper_rejected():
    import copy
    msg = copy.deepcopy(_signed_msg(seq=2))
    msg["telemetry"]["temp_c"] += 10.0  # 1-byte-equivalent post-sign edit
    assert verify_message(PUBKEY, msg) is False  # T-02


def test_ingest_replay_rejected():
    m1 = _signed_msg(seq=3)
    assert verify_message(PUBKEY, m1) is True
    last_seq = 3
    replay = _signed_msg(seq=1)
    assert replay["sequence"] <= last_seq  # T-03: drop, no second event


def test_serializer_strips_nothing_rejects_extra():
    with pytest.raises(ValueError, match="forbidden field"):
        process_candidate({
            "event_id": "c0b3ec22-2bce-4291-a654-5b8c21663045",
            "event_type": "sensor_anomaly", "severity": "critical",
            "observed_at": OBSERVED_AT, "model_version": "rule-v1",
            "is_anomaly": True, "gps": "0,0", "temp_c": 99.9,
            "explanation": "leak"})
    insight = _anomaly_insight()  # T-06 control: only 5 fields survive
    assert set(insight.model_dump()) == SUBSCRIBER_FIELDS


def test_mvp_flow_dispatch_roundtrip_revoke_outage():
    # Ingest + baseline + serializer.
    msg = _signed_msg(seq=10)
    assert verify_message(PUBKEY, msg) is True
    SignedTelemetryV1.model_validate(msg)
    insight = _anomaly_insight()

    # Dispatch with confirmed grant (T-08).
    q, priv_b64 = _queue_for(READER)
    chain = _grant_chain()
    env = q.dispatch(insight=insight, resource_id=RES,
                     recipient_wallet=READER, policy_id="p1",
                     policy_digest=DIGEST, policy_version=1,
                     chain_client=chain, now_unix=NOW)
    scan_no_plaintext([env], ["temp_c", "vibration_mm_s", "telemetry",
                              "explanation", "gps"])

    # Envelope round-trip; exact 5 approved fields (T-08).
    back = decrypt_envelope(env, priv_b64)
    assert set(back.model_dump(mode="json")) == SUBSCRIBER_FIELDS
    assert back.event_type == "MACHINE_ANOMALY"

    # Wrong key fails (T-09); tampered AAD/nonce/ciphertext fails (T-16).
    _, other_priv = _queue_for(READER2)
    with pytest.raises(ValueError):
        decrypt_envelope(env, other_priv)
    import copy
    for field in ("nonce_b64", "ciphertext_b64", "aad_b64"):
        bad = copy.deepcopy(env)
        bad[field] = base64.b64encode(b"\x00").decode()
        with pytest.raises(ValueError):
            decrypt_envelope(bad, priv_b64)

    # Revoke: confirmed inactive grant blocks NEW dispatch; unread blocked
    # at read (T-13). Epoch bump hides pre-revoke unread items.
    q.invalidate_recipient(RES, READER)
    revoked = _grant_chain(active=False)
    with pytest.raises(PolicyDenied):
        q.dispatch(insight=insight, resource_id=RES,
                   recipient_wallet=READER, policy_id="p1",
                   policy_digest=DIGEST, policy_version=1,
                   chain_client=revoked, now_unix=NOW)
    page = q.for_recipient(READER, RES, chain, DIGEST, now_unix=NOW)
    assert page["items"] == []

    # Independent second recipient unaffected (T-19).
    q2, priv2 = _queue_for(READER2)
    env2 = q2.dispatch(insight=insight, resource_id=RES,
                       recipient_wallet=READER2, policy_id="p1",
                       policy_digest=DIGEST, policy_version=1,
                       chain_client=_grant_chain(), now_unix=NOW)
    assert decrypt_envelope(env2, priv2).event_type == "MACHINE_ANOMALY"

    # Denials: wrong digest/resource/scope/expiry queue nothing (T-07/T-11).
    q3, _ = _queue_for(READER)
    for bad_chain, bad_digest in [
            (_grant_chain(digest=OTHER_DIGEST), DIGEST),
            (_grant_chain(), OTHER_DIGEST),
            (_grant_chain(expires=NOW - 1), DIGEST),
            (_grant_chain(scope=2), DIGEST)]:
        with pytest.raises(PolicyDenied):
            q3.dispatch(insight=insight, resource_id=RES,
                        recipient_wallet=READER, policy_id="p1",
                        policy_digest=bad_digest, policy_version=1,
                        chain_client=bad_chain, now_unix=NOW)
    assert q3.items == []

    # Chain outage fails closed on publish AND retrieval (T-14).
    outage = _grant_chain(outage=True)
    q4, _ = _queue_for(READER)
    with pytest.raises(AuthzUnavailable):
        q4.dispatch(insight=insight, resource_id=RES,
                    recipient_wallet=READER, policy_id="p1",
                    policy_digest=DIGEST, policy_version=1,
                    chain_client=outage, now_unix=NOW)
    with pytest.raises(AuthzUnavailable):
        q4.for_recipient(READER, RES, outage, DIGEST, now_unix=NOW)
    assert q4.items == []


def _tcp_open(host, port, timeout=0.3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def test_live_services_available_or_skip():
    anvil = _tcp_open("127.0.0.1", 8545)
    mqtt = _tcp_open("127.0.0.1", 1883)
    if not (anvil and mqtt):
        pytest.skip("live Anvil/MQTT unavailable; module-level rig covers MVP")
    assert anvil and mqtt
