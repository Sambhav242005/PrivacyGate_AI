"""PG-023 policy digest/gate tests against packages/shared golden fixtures."""
import json
import sys
from pathlib import Path

import pytest

GW_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(GW_SRC))
SHARED_FIX = Path(__file__).resolve().parent.parent.parent.parent / "packages" / "shared" / "fixtures"

from privacygate.domain.policy import (  # noqa: E402
    assert_policy_authorized,
    normalize_manifest,
    policy_digest,
)


def _load(name: str):
    return json.loads((SHARED_FIX / name).read_text(encoding="utf-8"))


def test_digest_matches_shared_fixture():
    manifest = _load("policy-manifest-v1.json")
    expected = _load("policy-digest.json")["policy_digest"]
    assert policy_digest(normalize_manifest(manifest)) == expected


def test_expired_rejected():
    manifest = _load("policy-manifest-v1.json")
    expected = _load("policy-digest.json")["policy_digest"]
    with pytest.raises(ValueError, match="expired"):
        assert_policy_authorized(manifest, expected, scope=1,
                                 now_unix=int(manifest["expires_at_unix"]) + 1)


def test_mismatched_digest_rejected():
    manifest = _load("policy-manifest-v1.json")
    tampered = dict(manifest, expires_at_unix=1900000000)
    with pytest.raises(ValueError, match="digest mismatch"):
        assert_policy_authorized(tampered, _load("policy-digest.json")["policy_digest"],
                                 scope=1, now_unix=1700000000)


def test_wrong_scope_rejected():
    manifest = _load("policy-manifest-v1.json")
    with pytest.raises(ValueError, match="scope"):
        assert_policy_authorized(manifest, "0x" + "00" * 32, scope=0,
                                 now_unix=1700000000)
