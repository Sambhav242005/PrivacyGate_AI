"""PG-043 C1/C2/C4: delivery <-> envelopes interop (unified DESIGN 7 KDF)."""
import base64
import copy
import sys
from pathlib import Path

import pytest

GW_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(GW_SRC))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

from privacygate.domain.schemas import InsightV1  # noqa: E402
from privacygate.security import envelopes  # noqa: E402
from privacygate.services.delivery import decrypt_envelope, encrypt_envelope  # noqa: E402

RES = "0x" + "aa" * 32
WALLET = "0x" + "22" * 20
INSIGHT = InsightV1(
    event_id="c0b3ec22-2bce-4291-a654-5b8c21663045",
    event_type="MACHINE_ANOMALY",
    severity="HIGH",
    observed_at="2026-10-14T12:00:00.000Z",
    model_version="isolation-forest-v1",
)


def _keypair():
    priv = X25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    priv_b64 = base64.b64encode(priv.private_bytes_raw()).decode()
    return pub_b64, priv_b64


def test_delivery_to_envelopes_interop():
    pub_b64, priv_b64 = _keypair()
    env = encrypt_envelope(
        INSIGHT, pub_b64, resource_id=RES, recipient_wallet=WALLET,
        policy_version=1, key_epoch=0)
    assert envelopes.decrypt_insight(dict(env), priv_b64) == INSIGHT.model_dump(mode="json")


def test_envelopes_to_delivery_interop():
    pub_b64, priv_b64 = _keypair()
    env = envelopes.encrypt_insight(
        INSIGHT.model_dump(mode="json"), pub_b64, resource_id=RES,
        recipient_wallet=WALLET, policy_version=1, key_epoch=0)
    back = decrypt_envelope(dict(env), priv_b64)
    assert back == INSIGHT


def test_delivery_rejects_header_mismatch():
    pub_b64, priv_b64 = _keypair()
    env = encrypt_envelope(
        INSIGHT, pub_b64, resource_id=RES, recipient_wallet=WALLET,
        policy_version=1, key_epoch=0)
    for field, bad in (("resource_id", "0x" + "bb" * 32),
                       ("recipient_wallet", "0x" + "33" * 20),
                       ("policy_version", 999),
                       ("key_epoch", 1),
                       ("delivery_id", "b769c092-0d35-4d05-b3b1-24f7326e43b2"),
                       ("schema_version", 999)):
        swapped = copy.deepcopy(env)
        swapped[field] = bad
        with pytest.raises(ValueError, match="[Aa][Aa][Dd]|decrypt failed"):
            decrypt_envelope(swapped, priv_b64)
