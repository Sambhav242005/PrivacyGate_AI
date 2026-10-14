"""PG-032 dispatch tests: fresh-chain gate, ciphertext-only queue.

Covers: no-grant denial, digest mismatch, expiry, chain-outage
fail-closed (503 mapping), queue plaintext scan, plus a positive
dispatch + decrypt roundtrip as control.
"""
import base64
import sys
from pathlib import Path

import pytest

GW_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(GW_SRC))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

from privacygate.chain.client import ChainUnavailable  # noqa: E402
from privacygate.chain.permissions import (  # noqa: E402
    AuthzUnavailable,
    PolicyDenied,
    authorize,
)
from privacygate.services.delivery import (  # noqa: E402
    DeliveryQueue,
    decrypt_envelope,
    scan_no_plaintext,
)
from privacygate.services.event_pipeline import process_candidate  # noqa: E402

RES = "0x" + "aa" * 32
READER = "0x" + "22" * 20
DIGEST = "0x" + "ab" * 32
OTHER_DIGEST = "0x" + "cd" * 32
NOW = 1700000000
EXPIRES = 1800000000

# Markers contain '-' / '.', which never appear in base64 -> no false hits.
RAW_TEMP_MARK = "93.2-xyz"
EXPLAIN_MARK = "super-secret-explanation-xyz"
DEVICE_MARK = "30ad1113-88be-44fd-90fd-683d0a3dd7b0"


def _candidate():
    return {"event_id": "c0b3ec22-2bce-4291-a654-5b8c21663045",
            "event_type": "sensor_anomaly", "severity": "critical",
            "observed_at": "2026-10-14T12:00:00.000Z",
            "model_version": "rule-v1", "is_anomaly": True}


class FakeChain:
    def __init__(self, grant=None, outage=False):
        self._grant = grant
        self.outage = outage

    def get_grant(self, resource_id, reader_wallet):
        if self.outage:
            raise ChainUnavailable("rpc down")
        assert resource_id == RES and reader_wallet == READER
        return dict(self._grant)

    def get_owner(self, resource_id):
        return "0x" + "11" * 20

    def current_block(self):
        if self.outage:
            raise ChainUnavailable("rpc down")
        return 8

    def get_receipt(self, tx_hash):
        if self.outage:
            raise ChainUnavailable("rpc down")
        return {"status": 1, "block_number": 8, "to": "0x" + "00" * 20,
                "tx_hash": tx_hash.lower()}

    def check_chain_id(self, expected):
        if self.outage:
            raise ChainUnavailable("rpc down")
        assert expected == 31337


def _grant(**kw):
    g = {"policy_digest": DIGEST, "expires_at": EXPIRES, "version": 1,
         "active": True, "scope": 1}
    g.update(kw)
    return g


def _keypair():
    priv = X25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    priv_b64 = base64.b64encode(priv.private_bytes_raw()).decode()
    return pub_b64, priv_b64


def _queue_with_key():
    q = DeliveryQueue()
    pub_b64, priv_b64 = _keypair()
    q.register_key(READER, pub_b64)
    return q, pub_b64, priv_b64


def test_positive_dispatch_decrypt_roundtrip():
    q, _, priv_b64 = _queue_with_key()
    insight = process_candidate(_candidate())
    assert insight is not None
    env = q.dispatch(insight=insight, resource_id=RES, recipient_wallet=READER,
                     policy_id="p1", policy_digest=DIGEST, policy_version=1,
                     chain_client=FakeChain(_grant()), now_unix=NOW)
    assert env["recipient_wallet"] == READER
    back = decrypt_envelope(env, priv_b64)
    assert back.event_id == insight.event_id and back.severity == "HIGH"


def test_no_grant_no_disclosure():
    q, _, _ = _queue_with_key()
    insight = process_candidate(_candidate())
    with pytest.raises(PolicyDenied):
        q.dispatch(insight=insight, resource_id=RES, recipient_wallet=READER,
                   policy_id="p1", policy_digest=DIGEST, policy_version=1,
                   chain_client=FakeChain(_grant(active=False)), now_unix=NOW)
    assert q.items == []


def test_mismatched_digest_denied():
    q, _, _ = _queue_with_key()
    insight = process_candidate(_candidate())
    with pytest.raises(PolicyDenied):
        q.dispatch(insight=insight, resource_id=RES, recipient_wallet=READER,
                   policy_id="p1", policy_digest=OTHER_DIGEST, policy_version=1,
                   chain_client=FakeChain(_grant()), now_unix=NOW)
    with pytest.raises(PolicyDenied):
        authorize(FakeChain(_grant()), RES, READER, OTHER_DIGEST, NOW)
    assert q.items == []


def test_expired_denied_and_maps_410():
    q, _, _ = _queue_with_key()
    chain = FakeChain(_grant(expires_at=NOW - 1))
    insight = process_candidate(_candidate())
    with pytest.raises(PolicyDenied) as ei:
        q.dispatch(insight=insight, resource_id=RES, recipient_wallet=READER,
                   policy_id="p1", policy_digest=DIGEST, policy_version=1,
                   chain_client=chain, now_unix=NOW)
    assert ei.value.reason == "expired"  # api/main maps expired -> HTTP 410
    assert q.items == []


def test_chain_outage_fail_closed_maps_503():
    q, _, _ = _queue_with_key()
    insight = process_candidate(_candidate())
    with pytest.raises(AuthzUnavailable):
        q.dispatch(insight=insight, resource_id=RES, recipient_wallet=READER,
                   policy_id="p1", policy_digest=DIGEST, policy_version=1,
                   chain_client=FakeChain(_grant(), outage=True), now_unix=NOW)
    with pytest.raises(AuthzUnavailable):  # read path also fail-closed
        q.for_recipient(READER, RES, FakeChain(_grant(), outage=True),
                        DIGEST, now_unix=NOW)
    assert q.items == []  # 503 AuthzUnavailable -> HTTP 503, nothing queued


def test_queue_has_no_plaintext():
    q, pub_b64, _ = _queue_with_key()
    raw_candidate = dict(_candidate(), **{
        "temp_c": RAW_TEMP_MARK, "explanation": EXPLAIN_MARK,
        "device_id": DEVICE_MARK})
    with pytest.raises(ValueError, match="forbidden field"):
        process_candidate(raw_candidate)  # serializer rejects junk first
    insight = process_candidate(_candidate())
    q.dispatch(insight=insight, resource_id=RES, recipient_wallet=READER,
               policy_id="p1", policy_digest=DIGEST, policy_version=1,
               chain_client=FakeChain(_grant()), now_unix=NOW)
    scan_no_plaintext(
        [it["envelope"] for it in q.items],
        [RAW_TEMP_MARK, EXPLAIN_MARK, DEVICE_MARK, "MACHINE_ANOMALY",
         "temp_c", "vibration_mm_s", "device_id", "telemetry"])
