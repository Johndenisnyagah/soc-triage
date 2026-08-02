"""The rule library.

Four rules ported from LogLens, plus two cloud rules. The port is not a copy:
LogLens rules matched on sshd message wording, so each one was implicitly an
SSH rule. These subscribe to `Category` and read `action`/`outcome`, which
means the brute-force rule fires on a CloudTrail ConsoleLogin burst without
knowing CloudTrail exists. That is the whole point of decision 5 in CLAUDE.md.

Every `technique` here is statically mapped. The LLM is never asked to supply
one for these -- it may only propose a technique where this field is None, and
even then the ID is validated against the ATT&CK catalog before use.
"""

from __future__ import annotations

from datetime import timedelta

from app.ingest.schema import Category, NormalizedEvent

from .engine import register
from .rules import (
    DistinctThresholdRule,
    SequenceRule,
    Severity,
    SingleEventRule,
    ThresholdRule,
)

#: Failures needed inside `BRUTE_FORCE_WINDOW` to call something a brute force.
#: Also the number of leading failures the follow-on success rule requires, so
#: "successful login after brute force" cannot fire on a burst too small to
#: have been reported as a brute force in the first place.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=10)


@register
class BruteForceAuthentication(ThresholdRule):
    """Repeated authentication failures against one entity.

    Source-agnostic by construction: it asks the event whether it is an
    authentication failure, not whether it is an sshd line. A run of failed
    ConsoleLogins from one IP trips this exactly as an ssh password spray does.
    """

    rule_id = "brute_force_auth"
    title = "Repeated authentication failures"
    severity = Severity.HIGH
    technique = "T1110"
    subscribes_to = frozenset({Category.AUTHENTICATION})

    window = BRUTE_FORCE_WINDOW
    threshold = BRUTE_FORCE_THRESHOLD

    def matches(self, event: NormalizedEvent) -> bool:
        return event.is_auth_failure()


@register
class SuccessfulLoginAfterBruteForce(SequenceRule):
    """A success landing on the tail of a failure burst.

    CRITICAL because the other rules describe an attempt and this one
    describes an outcome. The ordering carries all the meaning: the same two
    event kinds in the opposite order is somebody fat-fingering their password
    after they were already in.
    """

    rule_id = "brute_force_success"
    title = "Successful authentication after repeated failures"
    severity = Severity.CRITICAL
    technique = "T1110"
    subscribes_to = frozenset({Category.AUTHENTICATION})

    window = BRUTE_FORCE_WINDOW
    min_leading = BRUTE_FORCE_THRESHOLD

    def leading(self, event: NormalizedEvent) -> bool:
        return event.is_auth_failure()

    def trailing(self, event: NormalizedEvent) -> bool:
        return event.is_auth_success()


@register
class InvalidUserEnumeration(DistinctThresholdRule):
    """Attempts against three or more accounts that do not exist.

    Distinct from brute force: failures against a real account are somebody
    guessing a password, failures against accounts that were never there are
    somebody guessing *usernames*. Different technique, different response.

    Counts distinct usernames, not events. sshd logs two lines per rejected
    attempt -- `Invalid user admin` when the connection opens and `Failed
    password for invalid user admin` after the auth attempt -- so an event
    threshold reports six where three accounts were probed, and twenty retries
    of one username would trip an enumeration rule that is not looking at
    variety.

    Reads `extra["invalid_user"]`, which only the sshd parser sets. CLAUDE.md
    flags reaching into `extra` from a rule as the signal that a field wants
    promoting to a real column; this rule is the first caller, so the promotion
    is worth doing once a second source can populate it. Until then `.get()`
    means non-sshd events simply never match, rather than erroring.
    """

    rule_id = "invalid_user_enumeration"
    title = "Authentication attempts against non-existent accounts"
    severity = Severity.MEDIUM
    technique = "T1087"
    subscribes_to = frozenset({Category.AUTHENTICATION})

    window = timedelta(minutes=10)
    threshold = 3  # distinct usernames

    def matches(self, event: NormalizedEvent) -> bool:
        return event.is_auth_failure() and bool(event.extra.get("invalid_user"))

    def key(self, event: NormalizedEvent) -> str | None:
        # Casefolded so `Admin` and `admin` are one probed account, matching
        # how entity keys are normalised.
        return event.actor_name.casefold() if event.actor_name else None


@register
class AccessKeyAfterSuspiciousAuth(SequenceRule):
    """Long-lived credentials minted by an entity that just failed to log in.

    This is the pivot from access to persistence: a console session lasts hours
    and can be revoked, an access key lasts until somebody notices it. Seeing
    one created by an identity that was fumbling authentication minutes earlier
    is the shape of an attacker consolidating a foothold.

    The window is deliberately wider than the brute-force window -- the
    interesting gap is "same intrusion", not "same burst".
    """

    rule_id = "access_key_after_suspicious_auth"
    title = "Access key created after suspicious authentication"
    severity = Severity.HIGH
    technique = "T1098"
    subscribes_to = frozenset({Category.AUTHENTICATION, Category.IAM})

    window = timedelta(hours=1)
    min_leading = 1

    def leading(self, event: NormalizedEvent) -> bool:
        return event.is_auth_failure()

    def trailing(self, event: NormalizedEvent) -> bool:
        return event.action == "access_key_create"


@register
class CloudLoggingDisabled(SingleEventRule):
    """An attempt to stop the audit trail.

    Fires on the attempt, not the success. A denied StopLogging is arguably the
    louder signal: the credential is not merely active, somebody is steering it
    at the thing that would record what they do next. Outcome is carried in
    metadata so triage can rank a successful one higher without the rule
    needing to decide.
    """

    rule_id = "cloud_logging_disabled"
    title = "Cloud audit logging disabled"
    severity = Severity.HIGH
    technique = "T1562.008"
    subscribes_to = frozenset({Category.CONFIGURATION})

    def matches(self, event: NormalizedEvent) -> bool:
        return event.action == "logging_stop"

    def evaluate(self, ctx):  # type: ignore[override]
        for finding in super().evaluate(ctx):
            finding.metadata["outcome"] = str(finding.evidence[0].outcome)
            finding.metadata["target"] = finding.evidence[0].target_resource
            yield finding


#: Substrings that mark a managed policy as granting effective administrator
#: rights. Matched case-insensitively against the policy ARN.
_ADMIN_POLICY_MARKERS = ("administratoraccess", "poweruseraccess", "iamfullaccess")


@register
class AdminPolicyAttached(SingleEventRule):
    """Administrator-equivalent permissions granted to a principal.

    Not every `policy_attach` is interesting -- attaching ReadOnlyAccess is
    routine. The ARN is what separates housekeeping from privilege escalation,
    which is why the CloudTrail parser promotes `policyArn` into `extra`.
    """

    rule_id = "admin_policy_attached"
    title = "Administrator policy attached to principal"
    severity = Severity.HIGH
    technique = "T1098"
    subscribes_to = frozenset({Category.IAM})

    def matches(self, event: NormalizedEvent) -> bool:
        if event.action not in ("policy_attach", "policy_put"):
            return False
        arn = (event.extra.get("policy_arn") or "").casefold()
        return any(marker in arn for marker in _ADMIN_POLICY_MARKERS)

    def evaluate(self, ctx):  # type: ignore[override]
        for finding in super().evaluate(ctx):
            finding.metadata["policy_arn"] = finding.evidence[0].extra.get("policy_arn")
            yield finding
