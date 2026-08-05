"""ATT&CK catalog and validator.

Reads the committed `data/attack_catalog.json` -- no network. A suite that
fetched ATT&CK would fail on a plane, and worse, would pass or fail depending on
what MITRE published that morning.

Resolution rules that cannot be demonstrated against the shipped catalog are
tested against a small literal one. The parent-tactic fallback is the case in
point: no active technique in ATT&CK currently has an empty tactic list, so the
only way to exercise the branch is to build a catalog that has one.
"""

from __future__ import annotations

import json

import pytest

from app.detection.attack import (
    DEFAULT_CATALOG_PATH,
    Catalog,
    TechniqueInfo,
    default_catalog,
    resolve,
    tactics_for,
)


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return default_catalog()


# ---------------------------------------------------------------------------
# The committed file
# ---------------------------------------------------------------------------


def test_catalog_file_is_committed_and_populated(catalog):
    assert DEFAULT_CATALOG_PATH.exists()
    assert len(catalog) > 500


def test_catalog_records_its_provenance(catalog):
    """"Which ATT&CK is this?" must be answerable from the file itself, not
    inferred from a git timestamp."""
    meta = catalog.meta

    assert meta["source"].startswith("https://")
    assert meta["fetched_at"].endswith("Z")
    assert meta["attack_spec_version"]
    assert meta["content_last_modified"]
    assert meta["technique_count"] == len(catalog)


def test_catalog_is_pinned_to_a_release_tag_not_a_branch(catalog):
    """A bare SHA off a moving branch identifies the bytes but not the
    release. Both are recorded: the tag names the version, the SHA proves
    which bytes, and neither alone is enough."""
    meta = catalog.meta

    assert meta["source_ref"].startswith("ATT&CK-v")
    assert meta["source_ref"] not in ("master", "main")
    assert len(meta["source_commit"]) == 40
    # The URL must be built from the tag, so the file cannot silently have come
    # from somewhere other than the ref it claims.
    assert "master" not in meta["source"]


def test_catalog_is_valid_json_with_stable_ordering():
    """Sorted keys so an ATT&CK upgrade produces a readable diff."""
    payload = json.loads(DEFAULT_CATALOG_PATH.read_text(encoding="utf-8"))
    ids = list(payload["techniques"])

    assert ids == sorted(ids)


# ---------------------------------------------------------------------------
# Resolution against the real catalog
# ---------------------------------------------------------------------------


def test_valid_technique_resolves():
    info = resolve("T1110")

    assert isinstance(info, TechniqueInfo)
    assert info.technique_id == "T1110"
    assert info.name == "Brute Force"
    assert info.tactics == ("credential-access",)
    assert info.parent_id is None
    assert not info.is_subtechnique
    assert info.url.startswith("https://attack.mitre.org/")


def test_valid_subtechnique_resolves_and_knows_its_parent():
    info = resolve("T1003.001")

    assert info is not None
    assert info.is_subtechnique
    assert info.parent_id == "T1003"
    assert info.tactics == ("credential-access",)


def test_unknown_id_is_rejected():
    assert resolve("T9999") is None
    assert resolve("T1110.999") is None
    assert resolve("not-a-technique") is None


def test_empty_input_is_rejected():
    assert resolve(None) is None
    assert resolve("") is None


def test_deprecated_technique_is_rejected():
    """T1562.008 "Disable or Modify Cloud Logs" is retired -- ATT&CK replaced
    the whole T1562 family with T1685. A rule still pointing at it must get
    None, which is exactly how the stale mapping in the rule library surfaced.
    """
    assert resolve("T1562.008") is None
    assert resolve("T1562") is None


def test_case_is_normalized():
    assert resolve("t1110") == resolve("T1110")
    assert resolve("  t1003.001  ") == resolve("T1003.001")
    assert resolve("t1110").technique_id == "T1110"


def test_multi_tactic_technique_returns_all_its_tactics():
    """T1078 Valid Accounts spans four tactics. Reporting one would undercount
    the breadth incident severity is computed from."""
    info = resolve("T1078")

    assert len(info.tactics) == 4
    assert set(info.tactics) == {
        "stealth",
        "persistence",
        "privilege-escalation",
        "initial-access",
    }


def test_tactics_for_returns_empty_rather_than_raising():
    assert tactics_for("T9999") == ()
    assert tactics_for("T1562.008") == ()  # deprecated
    assert tactics_for(None) == ()
    assert tactics_for("T1110") == ("credential-access",)


# ---------------------------------------------------------------------------
# Resolution rules the shipped catalog cannot demonstrate
# ---------------------------------------------------------------------------


def _literal_catalog() -> Catalog:
    return Catalog(
        {
            "T9001": {
                "name": "Parent With Tactics",
                "tactics": ["persistence", "privilege-escalation"],
                "parent_id": None,
                "deprecated": False,
                "url": "https://example.invalid/T9001",
            },
            # The case the real catalog has no instance of.
            "T9001.001": {
                "name": "Child Without Tactics",
                "tactics": [],
                "parent_id": "T9001",
                "deprecated": False,
                "url": "https://example.invalid/T9001.001",
            },
            "T9001.002": {
                "name": "Child With Its Own Tactics",
                "tactics": ["discovery"],
                "parent_id": "T9001",
                "deprecated": False,
                "url": "https://example.invalid/T9001.002",
            },
            "T9002": {
                "name": "Deprecated Parent",
                "tactics": ["impact"],
                "parent_id": None,
                "deprecated": True,
                "url": "https://example.invalid/T9002",
            },
            "T9002.001": {
                "name": "Live Child Of Dead Parent",
                "tactics": [],
                "parent_id": "T9002",
                "deprecated": False,
                "url": "https://example.invalid/T9002.001",
            },
            "T9003.001": {
                "name": "Orphan",
                "tactics": [],
                "parent_id": "T9003",
                "deprecated": False,
                "url": "https://example.invalid/T9003.001",
            },
        }
    )


def test_subtechnique_with_no_tactics_inherits_the_parents():
    info = _literal_catalog().resolve("T9001.001")

    assert info is not None
    assert info.tactics == ("persistence", "privilege-escalation")


def test_subtechnique_with_its_own_tactics_does_not_inherit():
    """Inheritance is a fallback, not a merge -- a child that declares its own
    tactics is authoritative about them."""
    info = _literal_catalog().resolve("T9001.002")

    assert info.tactics == ("discovery",)


def test_a_live_subtechnique_inherits_from_a_deprecated_parent():
    """The parent's retirement says nothing about a child that is still
    current, and refusing to inherit would silently cost a tactic."""
    info = _literal_catalog().resolve("T9002.001")

    assert info is not None
    assert info.tactics == ("impact",)


def test_a_missing_parent_yields_no_tactics_rather_than_raising():
    info = _literal_catalog().resolve("T9003.001")

    assert info is not None
    assert info.tactics == ()


def test_deprecated_is_rejected_before_inheritance():
    assert _literal_catalog().resolve("T9002") is None


# ---------------------------------------------------------------------------
# The rule library's static mappings
# ---------------------------------------------------------------------------


def test_every_rule_technique_resolves():
    """The regression guard for stale mappings.

    ATT&CK restructures between releases. A rule pointing at a deprecated
    technique still looks correct in the source and contributes no tactic at
    runtime, so every incident containing it under-escalates with no error.
    Re-running the catalog build should fail here, not in production.
    """
    from app.detection.engine import registered_rules

    unresolved = {
        rule.rule_id: rule.technique
        for rule in registered_rules()
        if rule.technique and resolve(rule.technique) is None
    }

    assert unresolved == {}


def test_every_rule_technique_contributes_at_least_one_tactic():
    """Resolving is not enough -- a technique with no tactics would validate
    and still contribute nothing to severity."""
    from app.detection.engine import registered_rules

    tactless = {
        rule.rule_id: rule.technique
        for rule in registered_rules()
        if rule.technique and not tactics_for(rule.technique)
    }

    assert tactless == {}


# ---------------------------------------------------------------------------
# The enrichment candidate shortlists
# ---------------------------------------------------------------------------


def test_every_candidate_technique_resolves():
    """The same regression guard as for rule mappings, for the other place a
    technique ID is written down by hand.

    A dead candidate fails more quietly than a dead rule mapping: the ID goes
    into the prompt as an option, so the model is invited to pick it, and
    picking it is the *correct* answer to the question it was asked. The result
    is a proposed technique that contributes no tactic and looks like a model
    error rather than a configuration one.
    """
    from app.enrichment.candidates import CANDIDATES

    unresolved = {
        technique_id: str(category)
        for category, ids in CANDIDATES.items()
        for technique_id in ids
        if resolve(technique_id) is None
    }

    assert unresolved == {}


def test_every_candidate_technique_contributes_at_least_one_tactic():
    """`describe_candidates` renders the tactic list into the prompt, so a
    technique with none would be offered as a bare name with nothing to
    distinguish it."""
    from app.enrichment.candidates import CANDIDATES

    tactless = {
        technique_id: str(category)
        for category, ids in CANDIDATES.items()
        for technique_id in ids
        if not tactics_for(technique_id)
    }

    assert tactless == {}


def test_validate_candidates_accepts_the_shipped_map():
    """Runs at import already; called explicitly so the guard has a named test
    rather than only failing as a collection error somewhere unrelated."""
    from app.enrichment.candidates import validate_candidates

    validate_candidates()  # must not raise


def test_validate_candidates_rejects_a_deprecated_id(monkeypatch):
    """Proves the guard is not vacuous. T1562.007 Disable or Modify Cloud
    Firewall is exactly the shape of the failure this exists for: it was a
    reasonable candidate before v19 retired the Impair Defenses family, and it
    still reads as a real technique in the source.
    """
    from app.enrichment import candidates as candidates_mod
    from app.ingest.schema import Category

    monkeypatch.setattr(
        candidates_mod, "CANDIDATES", {Category.NETWORK: ("T1046", "T1562.007")}
    )

    with pytest.raises(candidates_mod.InvalidCandidateError) as excinfo:
        candidates_mod.validate_candidates()

    assert "T1562.007" in str(excinfo.value)
