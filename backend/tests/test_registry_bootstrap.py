"""Registries must be populated by importing the app, not by importing tests.

This has to run in a subprocess. Within a single pytest session every test
module is imported during collection, including the parser and rule tests --
which registers everything as a side effect and hides the bug this file exists
to catch. A fresh interpreter that imports only production modules is the sole
way to reproduce what a real caller does.

The two probes differ because the two layers have different entry points. The
parser registry has to be live after importing `app.main`, since uvicorn
imports exactly that and nothing more. The detection layer is not wired into
the API yet, so its entry point is the engine module a caller imports directly.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]

_PARSER_PROBE = """
import app.main  # noqa: F401 -- exactly what uvicorn imports, nothing more

from app.ingest.base import registered_parsers

print(",".join(sorted(str(p.source_type) for p in registered_parsers())))
"""

# Deliberately imports the engine rather than the package: if only
# `app/detection/__init__.py` populated the registry, importing a submodule
# directly would still work (Python runs the package __init__ first), but
# writing the probe this way proves the guarantee the engine docstring makes.
_RULE_PROBE = """
from app.detection.engine import registered_rules

print(",".join(sorted(r.rule_id for r in registered_rules())))
"""


def _probe(source: str) -> str:
    result = subprocess.run(
        [sys.executable, "-c", source],
        cwd=_BACKEND,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_importing_the_app_registers_every_parser():
    assert _probe(_PARSER_PROBE) == "aws_cloudtrail,syslog_sshd"


def test_importing_the_engine_registers_every_rule():
    assert _probe(_RULE_PROBE) == ",".join(
        sorted(
            [
                "access_key_after_suspicious_auth",
                "admin_policy_attached",
                "brute_force_auth",
                "brute_force_success",
                "cloud_logging_disabled",
                "invalid_user_enumeration",
            ]
        )
    )
