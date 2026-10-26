"""Loopback-only process entrypoint shared by PowerShell and integration tests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "apps/gateway/src"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=("validator", "gateway"))
    parser.add_argument("--config", type=Path, default=Path("var/v2/config.json"))
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8-sig"))
    if args.service == "validator":
        from privacygate_v2.ledger import Ledger, create_app

        ledger = Ledger(
            config["ledger_db"],
            config["validator_private_key_b64"],
            config["chain"]["identities"],
            config["chain"]["chain_id"],
        )
        app = create_app(ledger)
        port = args.port or 8010
    else:
        from privacygate_v2.api import create_app

        app = create_app(config)
        port = args.port or 8000
    uvicorn.run(app, host="127.0.0.1", port=port, access_log=False)


if __name__ == "__main__":
    main()
