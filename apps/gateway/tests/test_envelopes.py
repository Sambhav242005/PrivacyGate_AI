"""PG-030/PG-031 envelope crypto + key enrollment tests."""
import base64
import copy
import json
import sys
from pathlib import Path

import pytest

GW_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(GW_SRC))

from privacygate.security.envelopes import (  # noqa: E402
    decrypt_insight,
    encrypt_insight,
    generate_recipient_keypair,
)
from privacygate.storage.repository import Repository  # noqa: E402

RESOURCE = "0x" + "aa" * 32
WALLET = "0x" + "22" * 20
INSIGHT = {
    "event_id": "c0b3ec22-2bce-4291-a654-5b8c21663045",
    "event_type": "MACHINE_ANOMALY",
    "severity": "HIGH",
    "observed_at": "2026-10-14T12:00:00.000Z",
    "model_version": "isolation-forest-v1",
}


def _enc(priv=None, pub=None, **kw):
    if priv is None and pub is None:
        priv, pub = generate_recipient_keypair()
    args = {"resource_id": RESOURCE, "recipient_wallet": WALLET,
            "policy_version": 1, "key_epoch": 0}
    args.update(kw)
    env = encrypt_insight(INSIGHT, pub, **args)
    return env, priv


def test_round_trip_and_golden_shape():
    env, priv = _enc()
    assert set(env) == {"delivery_id", "schema_version", "resource_id",
                        "recipient_wallet", "policy_version", "key_epoch",
                        "ephemeral_public_key_b64", "nonce_b64", "aad_b64",
                        "ciphertext_b64"}
    assert len(base64.b64decode(env["ephemeral_public_key_b64"])) == 32
    assert len(base64.b64decode(env["nonce_b64"])) == 12
    aad = json.loads(base64.b64decode(env["aad_b64"]).decode())
    assert set(aad) == {"schema_version", "delivery_id", "event_id",
                        "resource_id", "recipient_wallet",
                        "policy_version", "key_epoch"}
    assert aad["event_id"] == INSIGHT["event_id"]
    assert decrypt_insight(env, priv) == INSIGHT


def test_per_delivery_randomness():
    _, pub = generate_recipient_keypair()
    priv_dummy, pub2 = generate_recipient_keypair()
    _ = (priv_dummy, pub2)
    e1, _ = _enc(pub=pub)
    e2, _ = _enc(pub=pub)
    assert e1["nonce_b64"] != e2["nonce_b64"]
    assert e1["ephemeral_public_key_b64"] != e2["ephemeral_public_key_b64"]
    assert e1["ciphertext_b64"] != e2["ciphertext_b64"]


def test_cross_key_fail():
    env, _ = _enc()
    wrong_priv, _ = generate_recipient_keypair()
    with pytest.raises(ValueError, match="decrypt failed"):
        decrypt_insight(env, wrong_priv)


def _tamper_b64(env, field, flip=0):
    raw = bytearray(base64.b64decode(env[field]))
    raw[flip] ^= 0x01
    out = copy.deepcopy(env)
    out[field] = base64.b64encode(bytes(raw)).decode()
    return out


def test_tamper_fail():
    env, priv = _enc()
    with pytest.raises(ValueError):
        decrypt_insight(_tamper_b64(env, "ciphertext_b64"), priv)
    with pytest.raises(ValueError):
        decrypt_insight(_tamper_b64(env, "nonce_b64"), priv)
    with pytest.raises(ValueError):
        decrypt_insight(_tamper_b64(env, "ephemeral_public_key_b64"), priv)
    # AAD byte flip breaks header mirror check or GCM auth.
    with pytest.raises(ValueError):
        decrypt_insight(_tamper_b64(env, "aad_b64", flip=5), priv)


def test_aad_mismatch_fail():
    env, priv = _enc()
    swapped = copy.deepcopy(env)
    swapped["policy_version"] = 999  # header no longer mirrors AAD
    with pytest.raises(ValueError, match="[Aa][Aa][Dd]"):
        decrypt_insight(swapped, priv)
    swapped_epoch = copy.deepcopy(env)
    swapped_epoch["key_epoch"] = env["key_epoch"] + 1
    with pytest.raises(ValueError):
        decrypt_insight(swapped_epoch, priv)


def test_encrypt_rejects_non_insight_fields():
    _, pub = generate_recipient_keypair()
    bad = dict(INSIGHT, temp_c=99.0)
    with pytest.raises(ValueError):
        encrypt_insight(bad, pub, resource_id=RESOURCE,
                        recipient_wallet=WALLET, policy_version=1, key_epoch=0)


def test_key_enrollment_ownership_and_length():
    repo = Repository()
    _, pub = generate_recipient_keypair()
    with pytest.raises(ValueError, match="32 bytes"):
        repo.save_x25519_pubkey(WALLET, base64.b64encode(b"short").decode(),
                                WALLET)
    other = "0x" + "33" * 20
    with pytest.raises(PermissionError):
        repo.save_x25519_pubkey(other, pub, WALLET)
    got = repo.save_x25519_pubkey(WALLET, pub, WALLET)
    assert got["rotated"] is False
    assert repo.get_x25519_pubkey(WALLET)["x25519_public_key_b64"] == pub


def test_key_change_bumps_epoch_and_invalidates():
    repo = Repository()
    _, pub1 = generate_recipient_keypair()
    _, pub2 = generate_recipient_keypair()
    repo.save_x25519_pubkey(WALLET, pub1, WALLET)
    repo.save_delivery("b769c092-0d35-4d05-b3b1-24f7326e43b2", WALLET,
                       RESOURCE, 0)
    assert len(repo.unread_deliveries(WALLET)) == 1
    res = repo.save_x25519_pubkey(WALLET, pub2, WALLET, resource_id=RESOURCE)
    assert res["rotated"] is True
    assert repo.get_key_epoch(RESOURCE, WALLET) == 1
    assert repo.unread_deliveries(WALLET) == []
    assert repo.get_delivery("b769c092-0d35-4d05-b3b1-24f7326e43b2")[
        "invalidated_at"] is not None
    # Same-key re-save is idempotent: no further bump.
    repo.save_x25519_pubkey(WALLET, pub2, WALLET, resource_id=RESOURCE)
    assert repo.get_key_epoch(RESOURCE, WALLET) == 1
