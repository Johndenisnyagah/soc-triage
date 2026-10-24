"""The committed demo must keep reproducing the README after New Year.

Syslog lines carry no year. `ParseContext.default_year` falls back to the
current year, which is right for live logs and wrong for a fixture: the sshd
sample describes 2026, and the CloudTrail sample it correlates with carries
explicit 2026 timestamps. Run in 2027 without a pinned year, the two files land
a year apart, the one-hour correlation gap splits the cross-source incident in
two, and the README's "verbatim" demo output stops being true.

Every other test passes `default_year="2026"`, so none of them would notice.
These two run with the clock moved to January 2027: one shows the hazard is
real, the other runs the actual demo script and checks it is immune.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import textwrap
from datetime import datetime, timezone

from app.ingest import base

BACKEND = pathlib.Path(__file__).resolve().parents[1]
SAMPLE_LOGS = BACKEND.parent / "sample_logs"
DEMO_SCRIPT = BACKEND / "scripts" / "run_detection.py"

FAKE_NOW = datetime(2027, 1, 15, 9, 0, tzinfo=timezone.utc)

# The README's demo output: two incidents, with these content-derived ids.
README_INCIDENT_IDS = ("INC-fe9ac9b7", "INC-27359b57")


class _January2027(datetime):
    @classmethod
    def now(cls, tz=None):  # noqa: D102 - mirrors datetime.now
        return FAKE_NOW if tz is None else FAKE_NOW.astimezone(tz)


def test_unpinned_syslog_year_follows_the_clock(client, db, monkeypatch):
    """The hazard: with no year supplied, sshd events take the current one."""
    from app.models import Event

    monkeypatch.setattr(base, "datetime", _January2027)
    response = client.post(
        "/api/ingest",
        files={"file": ("auth.log", (SAMPLE_LOGS / "auth.log").read_bytes(), "text/plain")},
    )
    assert response.status_code == 201, response.text

    years = {row.timestamp.year for row in db.query(Event).all()}
    assert years == {2027}


def test_demo_script_output_is_stable_after_year_rollover(tmp_path):
    """The fix: the demo pins the sample year, so 2027 changes nothing."""
    # sitecustomize runs before the script, so the clock is already moved when
    # the script imports the app. Patching the module global is enough because
    # ParseContext's default_factory reads `datetime` at call time.
    (tmp_path / "sitecustomize.py").write_text(
        textwrap.dedent(
            f"""
            from datetime import datetime, timezone
            import app.ingest.base as base

            _NOW = datetime({FAKE_NOW.year}, {FAKE_NOW.month}, {FAKE_NOW.day},
                            {FAKE_NOW.hour}, tzinfo=timezone.utc)

            class _Fake(datetime):
                @classmethod
                def now(cls, tz=None):
                    return _NOW if tz is None else _NOW.astimezone(tz)

            base.datetime = _Fake
            """
        ),
        encoding="utf-8",
    )

    env = dict(os.environ)
    # The script makes its own throwaway database; don't inherit the suite's.
    env.pop("DATABASE_URL", None)
    env["PYTHONPATH"] = os.pathsep.join([str(tmp_path), str(BACKEND)])

    result = subprocess.run(
        [sys.executable, str(DEMO_SCRIPT), str(SAMPLE_LOGS)],
        capture_output=True,
        text=True,
        env=env,
        cwd=BACKEND,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "incidents=2" in result.stdout
    for incident_id in README_INCIDENT_IDS:
        assert incident_id in result.stdout
