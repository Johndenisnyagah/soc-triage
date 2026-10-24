"""Upload the sample logs to a running API.

    python scripts/seed_samples.py ../sample_logs            # http://localhost:8000
    API_URL=http://api:8000 python scripts/seed_samples.py /samples

Used by `docker compose` to give a fresh stack something to show. Ingest is
idempotent (global dedup), so running it twice changes nothing. The sample year
is pinned for the same reason as in `run_detection.py`: syslog carries none.
"""

from __future__ import annotations

import os
import pathlib
import sys

import httpx

SAMPLE_FILES = ("auth.log", "cloudtrail.json")
SAMPLE_LOG_YEAR = 2026


def main() -> None:
    samples = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "../sample_logs")
    api = os.environ.get("API_URL", "http://localhost:8000").rstrip("/")
    with httpx.Client(base_url=api, timeout=30) as client:
        for name in SAMPLE_FILES:
            response = client.post(
                "/api/ingest",
                files={"file": (name, (samples / name).read_bytes(), "text/plain")},
                data={"default_year": str(SAMPLE_LOG_YEAR)},
            )
            response.raise_for_status()
            body = response.json()
            print(f"{name}: {body['events_persisted']} new, "
                  f"{body['duplicates_skipped']} already present")
        incidents = client.get("/api/incidents").json()
        print(f"{len(incidents)} incidents: " + ", ".join(i["incident_id"] for i in incidents))


if __name__ == "__main__":
    main()
