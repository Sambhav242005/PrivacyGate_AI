"""Provision a separate v2 runtime; never overwrite credentials or legacy data."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "apps/gateway/src"))


def protect(path: Path) -> None:
    """Restrict secrets to the current Windows account (or POSIX user)."""
    if os.name == "nt":
        identity = subprocess.check_output(["whoami"], text=True).strip()
        result = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{identity}:(OI)(CI)F"],
            capture_output=True,
            check=False,
            text=True,
        )
        if result.returncode:
            raise RuntimeError("Could not restrict runtime directory permissions")
    else:
        path.chmod(0o700 if path.is_dir() else 0o600)


def keypair() -> tuple[str, str]:
    key = Ed25519PrivateKey.generate()
    return (
        base64.b64encode(key.private_bytes_raw()).decode(),
        base64.b64encode(key.public_key().public_bytes_raw()).decode(),
    )


def bootstrap(root: Path) -> Path:
    from privacygate_v2.api import initialize_accounts
    from privacygate_v2.ledger import Ledger

    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    protect(root)
    target = root / "config.json"
    if target.exists():
        print("Existing v2 runtime preserved; no credentials regenerated.")
        return target
    if any(root.glob("*.db")) or (root / "credentials.json").exists():
        raise RuntimeError("Partial runtime found; inspect it before explicit reset")
    validator_secret, validator_public = keypair()
    accounts, identities, owner_keys, credentials = [], {}, {}, []
    for username, role in (("owner", "owner"), ("reader", "reader"), ("reader2", "reader")):
        account_id = str(uuid.uuid4())
        secret, public = keypair()
        password = secrets.token_urlsafe(20)
        identities[account_id] = public
        if role == "owner":
            owner_keys[account_id] = secret
        accounts.append(
            {"account_id": account_id, "username": username, "role": role, "password": password}
        )
        credentials.append(
            {"account_id": account_id, "username": username, "password": password, "role": role}
        )
    ledger = Ledger(root / "ledger.db", validator_secret, identities)
    public = ledger.public_config()
    config = {
        "runtime_root": str(root),
        "database_path": str(root / "gateway.db"),
        "ledger_db": str(root / "ledger.db"),
        "origin": "http://127.0.0.1:3000",
        "raw_key_b64": base64.b64encode(secrets.token_bytes(32)).decode(),
        "owner_private_keys": owner_keys,
        "validator_private_key_b64": validator_secret,
        "validator_public_key_b64": validator_public,
        "identities": identities,
        "chain_id": public["chain_id"],
        "chain": {**public, "url": "http://127.0.0.1:8010"},
        "accounts": accounts,
    }
    initialize_accounts(config)
    config.pop("accounts")
    for filename, value in (("config.json", config), ("credentials.json", credentials)):
        path = root / filename
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
        if os.name != "nt":
            protect(path)
    print(f"Provisioned v2 runtime: {root}")
    print("Local passwords are in the protected credentials.json file; do not share it.")
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=Path("var/v2"))
    bootstrap(parser.parse_args().runtime)
