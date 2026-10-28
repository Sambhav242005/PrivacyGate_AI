"""Local operator command for reviewed batch retraining; never prints sensor values."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "apps/gateway/src"))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from privacygate_v2.learning import LearningError, ModelStore, reviewed_candidate
from privacygate_v2.repository import Repository
from privacygate_v2.security import unb64
from privacygate_v2.service import load_config


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="var/v2/config.json")
    parser.add_argument("--owner", required=True, help="Provisioned owner username")
    parser.add_argument("--resource", required=True)
    parser.add_argument("--review", type=Path, help="Local sequence/label manifest, no raw values")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--activate", action="store_true")
    action.add_argument("--rollback", action="store_true")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        repo = Repository(config["database_path"])
        owner = repo.one("SELECT * FROM accounts WHERE username=?", (args.owner,))
        device = repo.one("SELECT owner_id FROM devices WHERE resource_id=?", (args.resource,))
        if (
            not owner
            or owner["role"] != "owner"
            or not device
            or device["owner_id"] != owner["account_id"]
        ):
            raise LearningError("OWNER_REQUIRED")
        cipher = AESGCM(unb64(config["raw_key_b64"], 32))
        store = ModelStore(Path(config["runtime_root"]), cipher)
        if args.rollback:
            report = store.rollback(args.resource)
        else:
            if not args.review or args.review.stat().st_size > 500_000:
                raise LearningError("REVIEW_REQUIRED_OR_TOO_LARGE")
            review = json.loads(args.review.read_text("utf-8-sig"))
            if review.get("resource_id") != args.resource:
                raise LearningError("REVIEW_RESOURCE_MISMATCH")
            report, bundle = reviewed_candidate(repo, cipher, store, owner, review)
            if args.activate:
                if not report["eligible"]:
                    print(json.dumps(report, indent=2))
                    return 2
                store.promote(args.resource, bundle, report["incumbent_version"])
                report["activated"] = True
        print(json.dumps(report, indent=2))
        return 0
    except LearningError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    except Exception:  # noqa: BLE001 - CLI boundary must never echo raw values or secret config
        print(json.dumps({"error": "RETRAINING_FAILED"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
