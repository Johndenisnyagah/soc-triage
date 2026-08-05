"""Candidate technique shortlists.

The point of this module is to change the question. Asking a model "which
ATT&CK technique describes this?" is open generation, and validation can only
catch IDs that do not exist -- it cannot catch T1078, which exists, resolves
cleanly, and is simply wrong for the evidence in front of it.

Asking instead "which of these six, or none?" converts the task to selection.
The wrong answers are bounded, "none" is a first-class option rather than
something the model has to resist producing, and a selection outside the list
is itself a validation failure -- `validate(..., allowed_techniques=...)`
enforces membership, without which the constraint would be advice in a prompt
rather than a check.

Candidates are keyed by event category and validated against the live ATT&CK
catalog at import: a candidate that is deprecated or unknown raises rather than
silently offering the model a dead ID.

Only categories a parser actually emits have entries. `Category.PROCESS` has
none because nothing produces process events until the Windows Security parser
lands at build-order step 7; a shortlist for a source that does not exist yet
could not be checked against real evidence, and `candidates_for` already
degrades to an empty list for an unmapped category. `Category.OTHER` is
deliberately empty too -- it is the bucket for events the parser could not
classify, and a shortlist for "unknown" is a guess offered with the authority
of a curated list.
"""

from __future__ import annotations

from app.detection import attack
from app.ingest.schema import Category

# Deliberately short. A list of forty is not multiple choice, it is open
# generation with extra steps -- and a long list pushes the real answer down
# where selection quality degrades.
#
# Every ID is checked at import by `validate_candidates()`, so the comments
# below cannot drift from the catalog without the process failing to start.
CANDIDATES: dict[Category, tuple[str, ...]] = {
    Category.AUTHENTICATION: (
        "T1110",        # Brute Force
        "T1110.001",    # Password Guessing
        "T1110.003",    # Password Spraying
        "T1078",        # Valid Accounts
        # Account Discovery: username enumeration shows up in the auth log, not
        # in a discovery-flavoured one, and `invalid_user_enumeration` already
        # maps here statically.
        "T1087",
    ),
    Category.IAM: (
        "T1098",        # Account Manipulation
        "T1098.001",    # Additional Cloud Credentials
        "T1136",        # Create Account
        "T1548",        # Abuse Elevation Control Mechanism
    ),
    Category.NETWORK: (
        "T1046",        # Network Service Discovery
        "T1580",        # Cloud Infrastructure Discovery
        # Cloud Firewall. The v19 replacement for T1562.007, which the Impair
        # Defenses retirement took with it: the family moved to T1685/T1686 and
        # T1562.007 resolves to None today. This is the `AuthorizeSecurityGroup
        # Ingress` case -- somebody opening a security group.
        "T1686.001",
    ),
    Category.STORAGE: (
        "T1530",        # Data from Cloud Storage
        "T1537",        # Transfer Data to Cloud Account
    ),
    Category.CONFIGURATION: (
        "T1685",        # Disable or Modify Tools
        "T1685.002",    # Disable or Modify Cloud Log
        "T1070",        # Indicator Removal
    ),
}

MAX_CANDIDATES = 8


class InvalidCandidateError(ValueError):
    """A configured candidate is not a usable technique in the current catalog."""


def validate_candidates() -> None:
    """Fail loudly at import rather than quietly offering a dead ID.

    An ATT&CK upgrade that deprecates a candidate should break the build, the
    same way `test_every_rule_technique_resolves` does for static mappings. The
    failure mode this prevents is quiet: a retired ID in the prompt is a wrong
    answer the model is being invited to pick, and one it would be *right* to
    pick given the list it was shown.
    """
    for category, ids in CANDIDATES.items():
        for technique_id in ids:
            if attack.resolve(technique_id) is None:
                raise InvalidCandidateError(
                    f"candidate {technique_id!r} for {category} does not resolve"
                )


def candidates_for(categories: set[Category]) -> list[str]:
    """Shortlist for an incident, deduplicated and bounded.

    Breadth-first across categories rather than category by category. The
    difference matters at the bound: an incident spanning authentication, IAM
    and configuration is the cross-source shape this whole pipeline is built
    to produce (decision 14), and taking each category's list in turn would
    spend all eight slots on authentication and offer the model no IAM
    technique at all for an incident whose central finding is an IAM one. The
    truncation would be invisible -- a shortlist that looks deliberate and
    silently cannot contain the right answer.

    Order is stable so prompts are reproducible: two runs over the same
    incident must produce the same prompt, or you cannot tell a model change
    from a prompt change. Categories are sorted, and within a category the
    declared order is preserved, so "stable" holds across interpreter runs and
    not merely within one.
    """
    ranked = [CANDIDATES.get(category, ()) for category in sorted(categories, key=str)]

    seen: list[str] = []
    for rank in range(max((len(ids) for ids in ranked), default=0)):
        for ids in ranked:
            if rank >= len(ids) or ids[rank] in seen:
                continue
            seen.append(ids[rank])
            if len(seen) >= MAX_CANDIDATES:
                return seen
    return seen


def describe_candidates(technique_ids: list[str]) -> str:
    """Render the shortlist for the prompt, with names so the model is
    choosing between meanings rather than between opaque identifiers."""
    lines = []
    for technique_id in technique_ids:
        info = attack.resolve(technique_id)
        if info:
            tactics = ", ".join(info.tactics)
            lines.append(f"  {technique_id} — {info.name} ({tactics})")
    lines.append("  NONE — no listed technique fits the evidence")
    return "\n".join(lines)


# At import, not on first use. A dead candidate is a configuration error, and
# the process should refuse to start rather than surface it as one incident
# enriched against a list containing an ID nothing can select correctly.
validate_candidates()
