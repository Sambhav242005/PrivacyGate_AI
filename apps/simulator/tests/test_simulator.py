"""PG-011 simulator tests: determinism, monotonic seq, invalid modes."""
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nacl.signing import SigningKey  # noqa: E402

from simulator.fixtures import generate_signed, generate_trace  # noqa: E402
from simulator.fixtures import make_invalid  # noqa: E402
from simulator.signing import canonical, verify_message  # noqa: E402


def test_determinism_same_seed_same_trace():
    k = SigningKey.generate()
    a = generate_signed(7, 10, k, mode="anomaly")
    b = generate_signed(7, 10, k, mode="anomaly")
    assert a == b
    c = generate_signed(8, 10, k, mode="anomaly")
    assert a != c


def test_sequence_monotonic_and_ranges():
    k = SigningKey.generate()
    msgs = generate_signed(1, 20, k)
    seqs = [m["sequence"] for m in msgs]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
    for m in msgs:
        t = m["telemetry"]
        assert -40 <= t["temp_c"] <= 200
        assert 0 <= t["vibration_mm_s"] <= 100
        assert isinstance(t["rpm"], int) and 0 <= t["rpm"] <= 30000
        assert len(base64.b64decode(m["signature_b64"])) == 64
        assert verify_message(bytes(k.verify_key), m)
        assert len(canonical(m)) <= 4096


def test_anomaly_differs_from_normal():
    k = SigningKey.generate()
    n = generate_trace(3, 10, mode="normal")
    a = generate_trace(3, 10, mode="anomaly")
    assert n != a
    # anomaly second half hotter on average
    assert sum(m["telemetry"]["temp_c"] for m in a[5:]) > sum(
        m["telemetry"]["temp_c"] for m in n[5:]
    )


def test_invalid_modes_differ():
    k = SigningKey.generate()
    for kind in ("tamper", "replay", "expired"):
        valid = generate_signed(9, 5, k)
        bad = make_invalid(valid, kind)
        assert bad != valid
        if kind == "tamper":
            assert not verify_message(bytes(k.verify_key), bad[-1])
        elif kind == "replay":
            seqs = [m["sequence"] for m in bad]
            assert len(set(seqs)) < len(seqs)  # duplicate seq
        else:
            assert bad[-1]["issued_at"] != valid[-1]["issued_at"]
