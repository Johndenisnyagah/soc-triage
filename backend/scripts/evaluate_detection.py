"""Score detection and correlation against the labelled corpus in `eval/`.

    python scripts/evaluate_detection.py              # print the results
    python scripts/evaluate_detection.py --write      # also refresh the committed
                                                      # corpus logs and the tables
                                                      # in docs/detection-evaluation.md

Ingests through the real endpoint into a throwaway SQLite file, exactly as
`run_detection.py` does, then sweeps `MAX_COOCCURRING_KEYS` over the same
persisted events. `tests/test_detection_evaluation.py` fails if the committed
corpus or tables drift from what this script produces.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys
import tempfile

_BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_BACKEND))

CORPUS_DIR = _BACKEND / "eval" / "corpus"
DOC = _BACKEND.parent / "docs" / "detection-evaluation.md"
START, END = "<!-- results:start -->", "<!-- results:end -->"

#: Values swept. 12 is the shipped default.
SWEEP = (2, 4, 6, 8, 12, 16, 32)
DEFAULT = 12


def render(runs: dict, scenarios: list, syslog: str, cloudtrail: str) -> str:
    """The generated part of the document, as markdown."""
    from eval.score import corpus_stats

    lines_, records = corpus_stats(syslog, cloudtrail)
    run = runs[DEFAULT]
    malicious = [s for s in scenarios if s.malicious]
    out: list[str] = []
    out.append(
        f"Corpus: {len(scenarios)} scenarios ({len(malicious)} malicious, "
        f"{len(scenarios) - len(malicious)} benign), {lines_} sshd lines and "
        f"{records} CloudTrail records, 14 September 2026 09:30–11:30 UTC.\n"
    )

    fp = run.of_kind("false_positive")
    out.append(f"### At the shipped default (`MAX_COOCCURRING_KEYS = {DEFAULT}`)\n")
    out.append("| Measure | Result |")
    out.append("|---|---|")
    out.append(f"| Expected detections that fired | **{run.hits} / {run.expected_total}** |")
    out.append(
        f"| Malicious scenarios detected | **{len(run.detected)} / {run.malicious_total}** |"
    )
    flagged = run.benign_flagged()
    out.append(
        f"| Benign scenarios left silent | **{run.benign_total - len(flagged)} / "
        f"{run.benign_total}** |"
    )
    out.append(f"| False-positive findings | **{len(fp)}** of {len(run.findings)} findings |")
    out.append(
        f"| Detected malicious scenarios in a clean incident of their own | "
        f"**{run.count('isolated')} / {len(run.detected)}** |"
    )
    out.append(f"| Findings mixing more than one scenario's activity | **{len(run.mixed)}** |")
    out.append("")

    out.append("### Per scenario\n")
    out.append("| Scenario | Truth | Expected | Outcome | Incident |")
    out.append("|---|---|---|---|---|")
    fp_rules: dict[str, list[str]] = {}
    for c in fp:
        for owner in c.owners:
            fp_rules.setdefault(owner, []).append(c.finding.rule_id)
    for s in scenarios:
        r = run.results[s.name]
        expected = ", ".join(f"`{e.rule_id}`" for e in s.expected) or "silence"
        if s.malicious:
            outcome = []
            if r.hits:
                outcome.append(f"hit {len(r.hits)}/{len(s.expected)}")
            if r.misses:
                outcome.append("**missed** " + ", ".join(f"`{e.rule_id}`" for e in r.misses))
            if not r.detected:
                incident = "—"
            elif r.split:
                incident = f"split across {len(r.incidents)}"
            elif r.merged:
                incident = f"merged with {len(r.merged_with)} other"
            else:
                incident = "isolated"
        else:
            rules = sorted(set(fp_rules.get(s.name, [])))
            outcome = (
                ["**false positive** " + ", ".join(f"`{x}`" for x in rules)]
                if rules else ["silent"]
            )
            incident = "—" if not rules else f"in {len(r.incidents)}"
        note = s.known_miss or s.known_false_positive
        tag = " †" if note else ""
        truth = "malicious" if s.malicious else "benign"
        out.append(f"| `{s.name}`{tag} | {truth} | {expected} | {'; '.join(outcome)} | {incident} |")
    out.append("")
    out.append("† labelled in advance as a known miss or known false positive:\n")
    for s in scenarios:
        note = s.known_miss or s.known_false_positive
        if note:
            out.append(f"- `{s.name}`: {note}")
    out.append("")

    out.append("### Sweeping `MAX_COOCCURRING_KEYS`\n")
    out.append(
        "| Value | Incidents | Findings shown | Isolated | Split | Merged | "
        "False positives | Mixed findings |"
    )
    out.append("|---|---|---|---|---|---|---|---|")
    for value, r in runs.items():
        label = f"**{value}** (default)" if value == DEFAULT else str(value)
        out.append(
            f"| {label} | {len(r.incidents)} | {len(r.findings)} | {r.count('isolated')} | "
            f"{r.count('split')} | {r.count('merged')} | {len(r.of_kind('false_positive'))} | "
            f"{len(r.mixed)} |"
        )
    out.append("")
    out.append(
        "Isolated, split and merged count detected malicious scenarios "
        f"(out of {len(run.detected)}). A scenario can be both split and merged."
    )
    return "\n".join(out)


def run_all() -> tuple[dict, list, str, str]:
    from fastapi.testclient import TestClient

    from app.database import SessionLocal
    from app.main import app
    from eval.corpus import build
    from eval.score import evaluate, ingest, load_events

    syslog, cloudtrail, scenarios = build()
    with TestClient(app) as client:
        ingest(client, syslog, cloudtrail)
    with SessionLocal() as session:
        events = load_events(session)
    runs = {value: evaluate(events, scenarios, max_keys=value) for value in SWEEP}
    return runs, scenarios, syslog, cloudtrail


def replace_between_markers(document: str, generated: str) -> str:
    head, rest = document.split(START, 1)
    _, tail = rest.split(END, 1)
    return f"{head}{START}\n{generated}\n{END}{tail}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true",
                        help="refresh eval/corpus/ and the tables in the doc")
    args = parser.parse_args()

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="soc-triage-eval-"))
    os.environ["DATABASE_URL"] = f"sqlite:///{(tmp / 'eval.db').as_posix()}"

    runs, scenarios, syslog, cloudtrail = run_all()
    generated = render(runs, scenarios, syslog, cloudtrail)
    print(generated)

    if args.write:
        CORPUS_DIR.mkdir(parents=True, exist_ok=True)
        (CORPUS_DIR / "auth.log").write_text(syslog, encoding="utf-8")
        (CORPUS_DIR / "cloudtrail.json").write_text(cloudtrail, encoding="utf-8")
        DOC.write_text(
            replace_between_markers(DOC.read_text(encoding="utf-8"), generated),
            encoding="utf-8",
        )
        print(f"\nwrote {CORPUS_DIR.relative_to(_BACKEND.parent)}/ and "
              f"{DOC.relative_to(_BACKEND.parent)}")


if __name__ == "__main__":
    main()
