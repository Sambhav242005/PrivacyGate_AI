"""Record actual model metrics; synthetic results do not establish field accuracy."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "apps/gateway/src"))

from privacygate_v2.model import evaluate_model


def main() -> None:
    report = {
        "recorded_at": datetime.now(UTC).isoformat(),
        "git_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "working_tree": "See accompanying run report; SHA alone does not include uncommitted changes",
        "python": platform.python_version(),
        "os": platform.platform(),
        "cpu": platform.processor(),
        "evaluation": evaluate_model(),
    }
    output = Path("docs/results/v2-model-evaluation.json")
    output.parent.mkdir(exist_ok=True, parents=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Measured evaluation written to {output}")


if __name__ == "__main__":
    main()
