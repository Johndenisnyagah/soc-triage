"""The registry must be populated by importing the app, not by importing tests.

This has to run in a subprocess. Within a single pytest session every test
module is imported during collection, including the parser tests -- which
registers the parsers as a side effect and hides the bug this file exists to
catch. A fresh interpreter that imports only `app.main` is the sole way to
reproduce what uvicorn actually does.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]

_PROBE = """
import app.main  # noqa: F401 -- exactly what uvicorn imports, nothing more

from app.ingest.base import registered_parsers

print(",".join(sorted(str(p.source_type) for p in registered_parsers())))
"""


def _probe() -> str:
    result = subprocess.run(
        [sys.executable, "-c", _PROBE],
        cwd=_BACKEND,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_importing_the_app_registers_every_parser():
    assert _probe() == "aws_cloudtrail,syslog_sshd"
