"""Derive a compact ATT&CK technique catalog from the MITRE CTI STIX bundle.

The upstream `enterprise-attack.json` is tens of megabytes of STIX objects, of
which detection needs five fields per technique. Vendoring the bundle would put
that weight in every clone and every container image for no benefit, so this
fetches it, projects out what the validator uses, and writes a derived file that
*is* committed.

Committing the derived file rather than fetching at runtime is the point: the
test suite must not need network, and a technique catalog that changes under you
between runs makes detection non-reproducible. The bundle version and fetch date
are recorded inside the output so "which ATT&CK is this?" has an answer without
guessing from a git timestamp.

    python scripts/build_attack_catalog.py

Re-run it to upgrade ATT&CK, and read the diff -- techniques get deprecated and
revoked between releases, and a rule statically mapped to one that vanished
should surface as a review, not a silent None.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

#: Pin to a release tag, never a branch. `master` moves between releases, so a
#: catalog built from it sits at an unnamed point partway to the next version --
#: a bare commit SHA identifies the bytes exactly and tells nobody which ATT&CK
#: they are running. Bump this deliberately and read the diff.
DEFAULT_REF = "ATT&CK-v19.1"

SOURCE_REPO = "mitre/cti"
BUNDLE_PATH = "enterprise-attack/enterprise-attack.json"


def source_url(ref: str) -> str:
    return (
        f"https://raw.githubusercontent.com/{SOURCE_REPO}/"
        f"{urllib.parse.quote(ref, safe='')}/{BUNDLE_PATH}"
    )

_BACKEND = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = _BACKEND / "data" / "attack_catalog.json"

#: STIX marks ATT&CK's own identifiers with this source name; anything else in
#: `external_references` is a citation, not a technique ID.
_ATTACK_SOURCE = "mitre-attack"


def fetch(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url, headers={"User-Agent": "soc-triage attack-catalog builder"}
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.loads(response.read().decode("utf-8"))


def _attack_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == _ATTACK_SOURCE and ref.get("external_id"):
            return ref["external_id"]
    return None


def _attack_url(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == _ATTACK_SOURCE:
            return ref.get("url", "")
    return ""


def _tactics(obj: dict[str, Any]) -> list[str]:
    """Tactic shortnames, in the order ATT&CK lists them.

    A technique can belong to several -- T1078 Valid Accounts spans four -- so
    this is a list, not a single value. Collapsing it to one would undercount
    tactic breadth, which is exactly what incident severity is derived from.
    """
    return [
        phase["phase_name"]
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == _ATTACK_SOURCE and phase.get("phase_name")
    ]


def _version_markers(bundle: dict[str, Any]) -> dict[str, str]:
    """Identify *which* ATT&CK this is.

    The master bundle carries no release number. `x_mitre_version` on an object
    is that object's own revision, and `x-mitre-collection` -- which does hold a
    release version -- is absent from this file. Rather than invent a version,
    record the markers that genuinely identify the content:

    * `attack_spec_version`, the highest ATT&CK spec any technique declares.
    * `content_last_modified`, the newest `modified` across all techniques.
      This is the practical answer to "is my catalog stale?".
    """
    patterns = [o for o in bundle.get("objects", []) if o.get("type") == "attack-pattern"]
    specs = sorted(
        {o.get("x_mitre_attack_spec_version", "") for o in patterns} - {""}
    )
    modified = sorted({o.get("modified", "") for o in patterns} - {""})
    return {
        "attack_spec_version": specs[-1] if specs else "unknown",
        "content_last_modified": modified[-1] if modified else "unknown",
    }


def _source_commit(ref: str, repo: str = SOURCE_REPO) -> str | None:
    """The commit the tag points at.

    The tag names the release, the SHA proves which bytes. Recording only the
    tag would trust that tags are never moved; recording only the SHA would
    leave a reader with no idea whether they have v18 or v19.

    Best-effort: a second network call against a rate-limited unauthenticated
    API. Failure records None rather than aborting a build that succeeded.
    """
    try:
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/commits/"
            f"{urllib.parse.quote(ref, safe='')}",
            headers={
                "User-Agent": "soc-triage attack-catalog builder",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())["sha"]
    except Exception as exc:  # noqa: BLE001 -- provenance is nice to have, not required
        print(f"warning: could not resolve source commit: {exc}", file=sys.stderr)
        return None


def build(bundle: dict[str, Any], source: str, ref: str) -> dict[str, Any]:
    techniques: dict[str, dict[str, Any]] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        technique_id = _attack_id(obj)
        if not technique_id:
            continue

        # `revoked` means replaced by another technique, `x_mitre_deprecated`
        # means retired outright. Both mean "do not map new detections to this",
        # which is the only distinction the validator cares about.
        deprecated = bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))

        # Derived from the ID rather than from STIX relationships: the dotted
        # form is definitional, and resolving `subtechnique-of` edges would mean
        # a second pass over the bundle for the same answer.
        parent_id = (
            technique_id.split(".", 1)[0] if "." in technique_id else None
        )

        techniques[technique_id] = {
            "name": obj.get("name", ""),
            "tactics": _tactics(obj),
            "parent_id": parent_id,
            "deprecated": deprecated,
            "url": _attack_url(obj),
        }

    active = sum(1 for t in techniques.values() if not t["deprecated"])
    return {
        "_meta": {
            "generator": "scripts/build_attack_catalog.py",
            "source": source,
            "source_repo": SOURCE_REPO,
            "source_ref": ref,
            "source_commit": _source_commit(ref),
            **_version_markers(bundle),
            "stix_spec_version": bundle.get("spec_version", "unknown"),
            "bundle_id": bundle.get("id", "unknown"),
            "fetched_at": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "technique_count": len(techniques),
            "active_count": active,
            "deprecated_count": len(techniques) - active,
            "subtechnique_count": sum(
                1 for t in techniques.values() if t["parent_id"]
            ),
        },
        "techniques": dict(sorted(techniques.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ref",
        default=DEFAULT_REF,
        help=f"CTI release tag to build from (default: {DEFAULT_REF})",
    )
    parser.add_argument(
        "--source", default=None, help="override the bundle URL entirely"
    )
    parser.add_argument("--output", default=DEFAULT_OUTPUT, type=pathlib.Path)
    args = parser.parse_args()

    source = args.source or source_url(args.ref)
    print(f"fetching {source}", file=sys.stderr)
    bundle = fetch(source)

    catalog = build(bundle, source, args.ref)
    if not catalog["techniques"]:
        sys.exit("no attack-pattern objects found -- refusing to write an empty catalog")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Sorted keys and a trailing newline so an ATT&CK upgrade produces a diff a
    # human can read rather than a single reordered line.
    args.output.write_text(
        json.dumps(catalog, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )

    meta = catalog["_meta"]
    print(
        f"wrote {args.output} -- {meta['source_ref']} "
        f"({(meta['source_commit'] or 'sha unknown')[:12]}), "
        f"spec {meta['attack_spec_version']}, "
        f"{meta['technique_count']} techniques "
        f"({meta['active_count']} active, {meta['deprecated_count']} deprecated, "
        f"{meta['subtechnique_count']} sub-techniques)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
