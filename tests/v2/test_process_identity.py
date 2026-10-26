"""Exercise the actual stop guard with both Windows shell JSON date types."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_recorded_process_identity_accepts_both_shell_dates_and_rejects_reused_pid():
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("Native Windows lifecycle check requires PowerShell")
    # The current process is inspected, never stopped; no runtime records change.
    script = r"""
    $ErrorActionPreference = 'Stop'
    . ./infra/scripts/v2/ProcessIdentity.ps1
    $process = Get-Process -Id $PID
    $utc = $process.StartTime.ToUniversalTime()
    $results = @{
        string_date = Test-RecordedProcessIdentity $process ($utc.ToString('o'))
        parsed_date = Test-RecordedProcessIdentity $process $utc
        offset_date = Test-RecordedProcessIdentity $process ([DateTimeOffset]$utc).ToOffset([TimeSpan]::FromHours(5.5))
        reused_pid = Test-RecordedProcessIdentity $process ($utc.AddTicks(-1))
        malformed = Test-RecordedProcessIdentity $process 'invalid-date'
    }
    $results | ConvertTo-Json -Compress
    """
    result = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert json.loads(result.stdout) == {
        "string_date": True,
        "parsed_date": True,
        "offset_date": True,
        "reused_pid": False,
        "malformed": False,
    }
