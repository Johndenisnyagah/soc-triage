"""A labelled evaluation corpus: one busy morning, attacks and benign activity mixed.

Every scenario states its ground truth *before* anything is run: which rules
should fire against which entity, which entities belong to one intrusion, and
which benign activity should stay silent. `scripts/evaluate_detection.py`
ingests the rendered logs through the real endpoint and scores what comes out.

Why one shared time window rather than one scenario per file: correlation only
goes wrong at batch scale. Unrelated intrusions that overlap in time and share
an ambient key (`user:root`, an office NAT address) are exactly the case
`MAX_COOCCURRING_KEYS` exists for, and a corpus of isolated scenarios would
never exercise it. Everything here happens on 14 September 2026, 09:30-11:30
UTC, inside the one-hour correlation gap of its neighbours.

Two kinds of label are deliberately honest rather than flattering:

* Malicious activity the rules are known not to catch (`low_and_slow`) is
  labelled with the detection it *should* get, so it scores as a miss.
* Benign activity the rules are known to flag (`forgotten_password`,
  `planned_logging_stop`) is labelled benign, so it scores as a false positive.

The corpus is synthetic, written to probe specific behaviours. It measures
whether the rules and correlation do what they claim on these cases; it is not
an estimate of real-world precision or recall.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from itertools import count

DAY = datetime(2026, 9, 14, tzinfo=UTC)
YEAR = DAY.year

ACCOUNT_PROD = "111122223333"
ACCOUNT_OPS = "444455556666"
OFFICE_NAT = "192.0.2.10"


def at(hh: int, mm: int, ss: int = 0) -> datetime:
    return DAY.replace(hour=hh, minute=mm, second=ss)


@dataclass(frozen=True)
class Expected:
    """A detection that should exist: `rule_id` firing with `anchor` in its evidence."""

    rule_id: str
    anchor: str


@dataclass
class Scenario:
    name: str
    malicious: bool
    description: str
    #: Detections that should fire. Empty for benign scenarios that should be silent.
    expected: list[Expected] = field(default_factory=list)
    #: Entity keys that identify this scenario's activity. A finding whose
    #: evidence touches one of them is attributed to this scenario, which is
    #: how the scorer decides whether an incident was split or merged.
    owns: frozenset[str] = frozenset()
    #: Benign scenarios only: the rules are known to flag this, and why.
    known_false_positive: str | None = None
    #: Malicious scenarios only: the rules are known to miss this, and why.
    known_miss: str | None = None


class _Builder:
    def __init__(self) -> None:
        self.syslog: list[tuple[datetime, str]] = []
        self.cloudtrail: list[dict] = []
        self._pid = count(20000)
        self._port = count(40000)
        self._event = count(1)

    # -- sshd -------------------------------------------------------------
    def _line(self, ts: datetime, host: str, message: str) -> None:
        stamp = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"
        self.syslog.append((ts, f"{stamp} {host} sshd[{next(self._pid)}]: {message}"))

    def ssh_fail(self, ts, host, user, ip, *, invalid: bool = False) -> None:
        who = f"invalid user {user}" if invalid else user
        self._line(ts, host, f"Failed password for {who} from {ip} port {next(self._port)} ssh2")

    def ssh_accept(self, ts, host, user, ip, method: str = "password") -> None:
        self._line(ts, host, f"Accepted {method} for {user} from {ip} port {next(self._port)} ssh2")

    # -- CloudTrail -------------------------------------------------------
    def _record(self, ts, account, user, ip, source, name, *, params=None,
                response=None, error=None, event_type="AwsApiCall") -> None:
        record = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDA{account}{user.upper()}"[:21],
                "arn": f"arn:aws:iam::{account}:user/{user}",
                "accountId": account,
                "userName": user,
            },
            "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": source,
            "eventName": name,
            "awsRegion": "eu-central-1",
            "sourceIPAddress": ip,
            "userAgent": "aws-cli/2.17.0 Python/3.12",
            "requestParameters": params,
            "responseElements": response,
            "eventID": f"00000000-0000-4000-8000-{next(self._event):012d}",
            "eventType": event_type,
            "recipientAccountId": account,
        }
        if error:
            record["errorCode"] = error
        self.cloudtrail.append(record)

    def console_login(self, ts, account, user, ip, *, success: bool) -> None:
        self._record(
            ts, account, user, ip, "signin.amazonaws.com", "ConsoleLogin",
            response={"ConsoleLogin": "Success" if success else "Failure"},
            event_type="AwsConsoleSignIn",
        )
        if not success:
            self.cloudtrail[-1]["errorMessage"] = "Failed authentication"

    def iam(self, ts, account, user, ip, event_name, **params) -> None:
        self._record(ts, account, user, ip, "iam.amazonaws.com", event_name, params=params or None)

    def cloudtrail_call(self, ts, account, user, ip, event_name, **params) -> None:
        self._record(
            ts, account, user, ip, "cloudtrail.amazonaws.com", event_name, params=params or None
        )


def _arn(account: str, user: str) -> str:
    return f"principal:arn:aws:iam::{account}:user/{user}"


def build() -> tuple[str, str, list[Scenario]]:
    """Render the corpus. Returns (auth.log text, cloudtrail.json text, scenarios)."""
    b = _Builder()
    scenarios: list[Scenario] = []

    # ---------------------------------------------------------------- malicious
    # 1. Four unrelated internet scanners, each brute-forcing root on its own
    #    host, overlapping in time. Four separate incidents: they share only
    #    `user:root`, which identifies nothing.
    scanners = [
        ("203.0.113.11", "web01", at(10, 2)),
        ("203.0.113.12", "web02", at(10, 6)),
        ("203.0.113.13", "web04", at(10, 11)),
        ("203.0.113.14", "app01", at(10, 15)),
    ]
    for i, (ip, host, start) in enumerate(scanners, 1):
        for n in range(8):
            b.ssh_fail(start + timedelta(seconds=11 * n), host, "root", ip)
        scenarios.append(Scenario(
            name=f"internet_scanner_{i}",
            malicious=True,
            description=f"8 root password failures from {ip} against {host} in 77 s",
            expected=[Expected("brute_force_auth", f"ip:{ip}")],
            owns=frozenset({f"ip:{ip}"}),
        ))

    # 2. One address spraying three common usernames across six hosts. One
    #    actor, so one incident -- however many hosts it touched.
    spray_ip = "198.51.100.200"
    spray_hosts = ["web01", "web02", "web03", "web04", "web05", "web06"]
    t = at(10, 20)
    for host in spray_hosts:
        for user in ("root", "admin", "ubuntu"):
            b.ssh_fail(t, host, user, spray_ip)
            t += timedelta(seconds=9)
    scenarios.append(Scenario(
        name="password_spray_across_fleet",
        malicious=True,
        description="18 failures from one address: root/admin/ubuntu against 6 hosts in under 3 min",
        expected=[Expected("brute_force_auth", f"ip:{spray_ip}")],
        owns=frozenset({f"ip:{spray_ip}"}),
    ))

    # 3. Distributed brute force: ten addresses, two attempts each, all against
    #    `admin` on one host. No single address crosses the threshold; the host
    #    and account do.
    t = at(10, 31)
    for n in range(10):
        ip = f"198.18.0.{10 + n}"
        for _ in range(2):
            b.ssh_fail(t, "web03", "admin", ip)
            t += timedelta(seconds=17)
    scenarios.append(Scenario(
        name="distributed_brute_force",
        malicious=True,
        description="20 admin failures on web03 from 10 addresses, 2 each, in under 6 min",
        expected=[Expected("brute_force_auth", "host:web03")],
        owns=frozenset({f"ip:198.18.0.{10 + n}" for n in range(10)}),
    ))

    # 4. Brute force that succeeds.
    bf_ip = "203.0.113.77"
    t = at(10, 40)
    for n in range(7):
        b.ssh_fail(t + timedelta(seconds=8 * n), "db01", "root", bf_ip)
    b.ssh_accept(t + timedelta(seconds=70), "db01", "root", bf_ip)
    scenarios.append(Scenario(
        name="brute_force_then_success",
        malicious=True,
        description="7 root failures on db01 then an accepted password, same address",
        expected=[
            Expected("brute_force_auth", f"ip:{bf_ip}"),
            Expected("brute_force_success", f"ip:{bf_ip}"),
        ],
        owns=frozenset({f"ip:{bf_ip}"}),
    ))

    # 5. Username enumeration: five different non-existent accounts, once each.
    enum_ip = "203.0.113.91"
    t = at(10, 44)
    for n, user in enumerate(("oracle", "test", "guest", "postgres", "git")):
        b.ssh_fail(t + timedelta(seconds=20 * n), "bastion01", user, enum_ip, invalid=True)
    scenarios.append(Scenario(
        name="username_enumeration",
        malicious=True,
        description="5 distinct invalid usernames from one address against bastion01",
        expected=[Expected("invalid_user_enumeration", f"ip:{enum_ip}")],
        owns=frozenset({f"ip:{enum_ip}"}),
    ))

    # 6. Low-and-slow brute force: one attempt every three minutes for an hour.
    #    Never more than four inside the ten-minute window, so the threshold
    #    rule cannot see it. Labelled with the detection it deserves.
    slow_ip = "203.0.113.140"
    for n in range(20):
        b.ssh_fail(at(9, 45) + timedelta(minutes=3 * n), "app02", "deploy", slow_ip)
    scenarios.append(Scenario(
        name="low_and_slow",
        malicious=True,
        description="20 deploy failures on app02, one every 3 min for an hour",
        expected=[Expected("brute_force_auth", f"ip:{slow_ip}")],
        owns=frozenset({f"ip:{slow_ip}"}),
        known_miss=(
            "BRUTE_FORCE_THRESHOLD is 5 failures in 10 minutes; at one every 3 "
            "minutes the window never holds more than 4."
        ),
    ))

    # 7. Cloud account takeover: console brute force, success, a new access
    #    key, then administrator rights.
    cloud_ip = "198.51.100.66"
    victim = "ci-runner"
    t = at(10, 50)
    for n in range(6):
        b.console_login(t + timedelta(seconds=15 * n), ACCOUNT_PROD, victim, cloud_ip, success=False)
    b.console_login(t + timedelta(seconds=110), ACCOUNT_PROD, victim, cloud_ip, success=True)
    b.iam(t + timedelta(minutes=4), ACCOUNT_PROD, victim, cloud_ip, "CreateAccessKey", userName=victim)
    b.iam(t + timedelta(minutes=6), ACCOUNT_PROD, victim, cloud_ip, "AttachUserPolicy",
          userName=victim, policyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    scenarios.append(Scenario(
        name="cloud_account_takeover",
        malicious=True,
        description="6 failed console logins, a success, CreateAccessKey, AdministratorAccess attached",
        expected=[
            Expected("brute_force_auth", _arn(ACCOUNT_PROD, victim)),
            Expected("brute_force_success", _arn(ACCOUNT_PROD, victim)),
            Expected("access_key_after_suspicious_auth", _arn(ACCOUNT_PROD, victim)),
            Expected("admin_policy_attached", _arn(ACCOUNT_PROD, victim)),
        ],
        owns=frozenset({f"ip:{cloud_ip}", _arn(ACCOUNT_PROD, victim)}),
    ))

    # ------------------------------------------------------------------ benign
    # 8. A user who forgot their password: six failures, then in. From the
    #    office NAT. Indistinguishable from scenario 4 by these rules.
    t = at(9, 52)
    for n in range(6):
        b.ssh_fail(t + timedelta(seconds=25 * n), "web02", "alice", OFFICE_NAT)
    b.ssh_accept(t + timedelta(seconds=180), "web02", "alice", OFFICE_NAT)
    scenarios.append(Scenario(
        name="forgotten_password",
        malicious=False,
        description="alice fails 6 times on web02 from the office NAT, then logs in",
        owns=frozenset({"user:alice"}),
        known_false_positive=(
            "Six failures then a success is the brute-force-success shape; the "
            "rules have no notion of a known user at a known address."
        ),
    ))

    # 9. A monitoring check with a stale password, failing every 5 minutes.
    for n in range(24):
        b.ssh_fail(at(9, 30) + timedelta(minutes=5 * n), "web05", "nagios", "192.0.2.50")
    scenarios.append(Scenario(
        name="monitoring_probe",
        malicious=False,
        description="nagios fails once every 5 min on web05 for two hours",
        owns=frozenset({"ip:192.0.2.50"}),
    ))

    # 10. Two username typos, then the right one.
    b.ssh_fail(at(10, 5), "web01", "alcie", OFFICE_NAT, invalid=True)
    b.ssh_fail(at(10, 5, 20), "web01", "aliec", OFFICE_NAT, invalid=True)
    b.ssh_accept(at(10, 5, 45), "web01", "alice", OFFICE_NAT)
    scenarios.append(Scenario(
        name="username_typos",
        malicious=False,
        description="two mistyped usernames from the office NAT, then a normal login",
        owns=frozenset({"user:alcie", "user:aliec"}),
    ))

    # 11. Key-based logins across the fleet: the normal background.
    for n, host in enumerate(["web01", "web03", "web06", "db01", "app01", "bastion01"]):
        b.ssh_accept(at(9, 40) + timedelta(minutes=7 * n), host, "ubuntu", OFFICE_NAT, "publickey")
    scenarios.append(Scenario(
        name="routine_key_logins",
        malicious=False,
        description="6 publickey logins for ubuntu across the fleet from the office NAT",
        owns=frozenset(),
    ))

    # 12. Routine IAM work: read-only policy, an access key for a new CI user,
    #     no suspicious authentication anywhere near it.
    ops = "ops-admin"
    b.console_login(at(9, 58), ACCOUNT_OPS, ops, OFFICE_NAT, success=True)
    b.iam(at(10, 3), ACCOUNT_OPS, ops, OFFICE_NAT, "AttachUserPolicy",
          userName="ci-bot", policyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")
    b.iam(at(10, 4), ACCOUNT_OPS, ops, OFFICE_NAT, "CreateAccessKey", userName="ci-bot")
    scenarios.append(Scenario(
        name="routine_iam_changes",
        malicious=False,
        description="ops-admin attaches ReadOnlyAccess and creates an access key for ci-bot",
        owns=frozenset({_arn(ACCOUNT_OPS, ops)}),
    ))

    # 13. A planned change that stops a test trail.
    eng = "platform-eng"
    b.cloudtrail_call(at(11, 10), ACCOUNT_OPS, eng, OFFICE_NAT, "StopLogging", name="sandbox-trail")
    scenarios.append(Scenario(
        name="planned_logging_stop",
        malicious=False,
        description="platform-eng stops a sandbox trail during planned maintenance",
        owns=frozenset({_arn(ACCOUNT_OPS, eng)}),
        known_false_positive=(
            "cloud_logging_disabled fires on any StopLogging by design: the logs "
            "cannot tell a change ticket from an attacker covering tracks."
        ),
    ))

    syslog = "\n".join(line for _, line in sorted(b.syslog, key=lambda x: x[0])) + "\n"
    cloudtrail = json.dumps(
        {"Records": sorted(b.cloudtrail, key=lambda r: r["eventTime"])}, indent=1
    ) + "\n"
    return syslog, cloudtrail, scenarios
