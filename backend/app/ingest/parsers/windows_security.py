"""Windows Security events, as Windows Event XML.

The input is the XML rendering of the Security channel: what
`wevtutil qe Security /f:xml` prints, what Event Viewer's "Save as XML" writes,
and what EVTX converters such as `evtx_dump` produce. Binary `.evtx` is not read
directly -- convert it first. One rendering, done carefully, beats three done
loosely, and XML is the one every Windows tool can emit.

Five decisions, each answering a specific way this source goes wrong:

* **Per-event parsing, never whole-document.** The text is split on
  `<Event ...>...</Event>` boundaries and each record is parsed on its own. A
  single malformed record -- truncated by a log shipper, or hand-edited -- costs
  that record, not the file (decision 4). A whole-document parse would turn one
  bad byte into zero events.

* **No DTDs, ever.** Windows never emits a DOCTYPE or entity declaration, so
  their presence means the file did not come from Windows. A record containing
  `<!` is rejected before it reaches the XML parser, which closes entity
  expansion attacks without a third-party dependency. Records are parsed
  separately, so a DTD at the top of the file cannot define entities for them.

* **`target_resource` is the channel.** `EventRecordID` is unique per channel
  per host, so the channel has to be in the dedup hash, and `target_resource`
  is the field that carries it there (decision 11). The group name in a
  membership change goes in `extra` instead.

* **No SID as a principal.** Failed logons for accounts that do not exist carry
  the NULL SID `S-1-0-0`; machine and service logons carry `S-1-5-18`. As
  `principal:` keys -- the highest-precedence key in correlation -- those would
  join every unrelated failure on every host into one incident. SIDs go in
  `extra`; the account name is the `user:` key.

* **Only logons a person or an attacker could make count as authentication.**
  Service (5), batch (4) and system (0) logons, and logons by computer accounts
  (`HOST$`), happen continuously on every Windows machine. Emitted as
  successful authentication, any of them becomes the trailing event of
  `brute_force_success` -- the same false-positive shape as CloudTrail's
  `GetCallerIdentity`. They are counted as skipped instead.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from ..base import BaseParser, ParseContext, register
from ..schema import ActorType, Category, NormalizedEvent, Outcome, SourceType

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# `<Event` followed by whitespace or `>`, so `<EventData>` and `<EventID>` never
# start a record; `</Event>` with the `>` attached, so `</EventData>` never ends one.
_RECORD = re.compile(r"<Event[\s>].*?</Event>", re.DOTALL)

#: SubStatus on a 4625 meaning "the user name does not exist" -- the Windows
#: equivalent of sshd's "invalid user", which `invalid_user_enumeration` reads.
_NO_SUCH_USER = "0xc0000064"

#: Logon types an interactive user or a remote attacker produces:
#: 2 interactive, 3 network (SMB, WinRM), 7 unlock, 8 network cleartext,
#: 9 new credentials (runas /netonly), 10 RemoteInteractive (RDP),
#: 11 cached interactive.
_PERSON_LOGON_TYPES = {"2", "3", "7", "8", "9", "10", "11"}

_GROUP_MEMBER_ADD = {"4728", "4732", "4756"}  # global, local, universal groups

#: Recognised event IDs -> (category, action). Anything else is skipped.
_EVENTS: dict[str, tuple[Category, str]] = {
    "4624": (Category.AUTHENTICATION, "login"),
    "4625": (Category.AUTHENTICATION, "login"),
    "4720": (Category.IAM, "user_create"),
    "4726": (Category.IAM, "user_delete"),
    "4728": (Category.IAM, "group_member_add"),
    "4732": (Category.IAM, "group_member_add"),
    "4756": (Category.IAM, "group_member_add"),
    "4740": (Category.IAM, "account_lockout"),
    "4688": (Category.PROCESS, "process_create"),
    "1102": (Category.CONFIGURATION, "audit_log_clear"),
}


class _Skip(Exception):
    """A well-formed record this parser recognises but does not model."""


@register
class WindowsSecurityXmlParser(BaseParser):
    source_type = SourceType.WINDOWS_SECURITY

    @classmethod
    def sniff(cls, sample: str) -> float:
        if "<Event" not in sample:
            return 0.0
        markers = sum(
            marker in sample
            for marker in (
                "schemas.microsoft.com/win/2004/08/events/event",
                "<EventID",
                "<EventRecordID>",
                "<Computer>",
            )
        )
        return min(0.95, 0.25 * markers)

    def parse(self, content: str, ctx: ParseContext) -> Iterator[NormalizedEvent]:
        for index, match in enumerate(_RECORD.finditer(content), start=1):
            ctx.stats.lines_read += 1
            chunk = match.group(0).strip()
            if "<!" in chunk:
                ctx.stats.record_error(index, "DTD or entity declaration rejected", chunk)
                continue
            try:
                element = ET.fromstring(chunk)
            except ET.ParseError as exc:
                ctx.stats.record_error(index, f"malformed XML: {exc}", chunk)
                continue
            try:
                event = self._to_event(element, chunk, ctx)
            except _Skip:
                ctx.stats.lines_skipped += 1
                continue
            except Exception as exc:  # noqa: BLE001 - one bad record must not abort ingest
                ctx.stats.record_error(index, f"unusable record: {exc}", chunk)
                continue
            ctx.stats.events_emitted += 1
            yield event

    # -- one record -----------------------------------------------------

    def _to_event(self, element: ET.Element, raw: str, ctx: ParseContext) -> NormalizedEvent:
        system = element.find(f"{_NS}System")
        if system is None:
            raise ValueError("no <System> block")

        event_id = _text(system, "EventID")
        if event_id not in _EVENTS:
            raise _Skip
        category, action = _EVENTS[event_id]
        data = _event_data(element)

        record_id = _text(system, "EventRecordID")
        channel = _text(system, "Channel") or "Security"
        created = system.find(f"{_NS}TimeCreated")
        timestamp = _timestamp(created.get("SystemTime") if created is not None else None)
        if timestamp is None:
            raise ValueError("no usable TimeCreated/@SystemTime")

        event = NormalizedEvent(
            source_type=self.source_type,
            raw=raw,
            source_event_id=record_id,
            timestamp=timestamp,
            category=category,
            action=action,
            host=_text(system, "Computer") or ctx.default_host,
            target_resource=channel,
            extra={"event_id": int(event_id), "channel": channel},
        )

        if event_id in ("4624", "4625"):
            self._logon(event, event_id, data)
        elif event_id in ("4720", "4726"):
            self._subject(event, data)
            event.outcome = Outcome.SUCCESS
            event.extra["target_user"] = data.get("TargetUserName")
            event.extra["target_sid"] = data.get("TargetSid")
        elif event_id in _GROUP_MEMBER_ADD:
            self._subject(event, data)
            event.outcome = Outcome.SUCCESS
            # In membership events TargetUserName is the *group*.
            event.extra["group"] = data.get("TargetUserName")
            event.extra["group_sid"] = data.get("TargetSid")
            event.extra["member"] = data.get("MemberName")
            event.extra["member_sid"] = data.get("MemberSid")
        elif event_id == "4740":
            event.outcome = Outcome.SUCCESS
            event.actor_name = _account(data.get("TargetUserName"))
            event.actor_type = ActorType.USER
            event.extra["caller_computer"] = data.get("TargetDomainName")
        elif event_id == "4688":
            self._subject(event, data)
            event.outcome = Outcome.SUCCESS
            event.extra["process"] = data.get("NewProcessName")
            # Attacker-controlled, like a user agent: evidence, never instruction.
            event.extra["command_line"] = data.get("CommandLine")
            event.extra["parent_process"] = data.get("ParentProcessName")
        elif event_id == "1102":
            # 1102 carries its subject in <UserData>, not <EventData>.
            event.outcome = Outcome.SUCCESS
            subject = _user_data(element)
            event.actor_name = _account(subject.get("SubjectUserName"))
            event.actor_type = ActorType.USER if event.actor_name else ActorType.UNKNOWN
            event.extra["subject_sid"] = subject.get("SubjectUserSid")
        return event

    def _logon(self, event: NormalizedEvent, event_id: str, data: dict[str, str]) -> None:
        user = _account(data.get("TargetUserName"))
        logon_type = data.get("LogonType")
        if event_id == "4624" and (
            logon_type not in _PERSON_LOGON_TYPES or (user or "").endswith("$")
        ):
            raise _Skip  # service, batch, system or machine-account logon

        status = (data.get("SubStatus") or "").lower()
        event.outcome = Outcome.SUCCESS if event_id == "4624" else Outcome.FAILURE
        event.actor_name = user
        event.actor_type = ActorType.USER
        event.source_ip = _address(data.get("IpAddress"))
        port = data.get("IpPort")
        event.source_port = int(port) if port and port.isdigit() and port != "0" else None
        event.extra.update(
            {
                "logon_type": int(logon_type) if logon_type and logon_type.isdigit() else None,
                "target_domain": data.get("TargetDomainName"),
                "target_sid": data.get("TargetUserSid"),
                "workstation": data.get("WorkstationName"),
                "auth_package": data.get("AuthenticationPackageName"),
                "invalid_user": event_id == "4625" and status == _NO_SUCH_USER,
            }
        )
        if event_id == "4625":
            event.extra["status"] = data.get("Status")
            event.extra["sub_status"] = data.get("SubStatus")

    @staticmethod
    def _subject(event: NormalizedEvent, data: dict[str, str]) -> None:
        """The account that *performed* an account or process change."""
        event.actor_name = _account(data.get("SubjectUserName"))
        event.actor_type = ActorType.USER if event.actor_name else ActorType.UNKNOWN
        event.extra["subject_sid"] = data.get("SubjectUserSid")
        event.extra["subject_domain"] = data.get("SubjectDomainName")


# -- helpers ------------------------------------------------------------


def _text(parent: ET.Element, tag: str) -> str | None:
    child = parent.find(f"{_NS}{tag}")
    if child is None or child.text is None:
        return None
    return child.text.strip() or None


def _event_data(element: ET.Element) -> dict[str, str]:
    block = element.find(f"{_NS}EventData")
    if block is None:
        return {}
    return {
        item.get("Name"): (item.text or "").strip()
        for item in block.findall(f"{_NS}Data")
        if item.get("Name")
    }


def _user_data(element: ET.Element) -> dict[str, Any]:
    """`<UserData>` holds a provider-specific element; read its children by local name."""
    block = element.find(f"{_NS}UserData")
    if block is None:
        return {}
    values: dict[str, Any] = {}
    for child in block.iter():
        name = child.tag.rsplit("}", 1)[-1]
        if child.text and child.text.strip():
            values[name] = child.text.strip()
    return values


def _account(name: str | None) -> str | None:
    """Windows writes `-` for "no account"."""
    if not name or name == "-":
        return None
    return name


def _address(value: str | None) -> str | None:
    """`-` means no network address (a local logon)."""
    if not value or value == "-":
        return None
    # IPv4-mapped IPv6 (`::ffff:203.0.113.5`) is the same address as sshd and
    # CloudTrail report; normalising it is what lets the ip: key join them.
    if value.lower().startswith("::ffff:") and "." in value:
        return value[7:]
    return value


def _timestamp(value: str | None) -> datetime | None:
    """`2026-08-02T04:41:07.1234567Z` -- Windows writes 7 fractional digits,
    one more than `datetime` holds."""
    if not value:
        return None
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z?", value.strip())
    if not match:
        return None
    base = datetime.fromisoformat(match.group(1)).replace(tzinfo=UTC)
    fraction = (match.group(2) or "0")[:6].ljust(6, "0")
    return base.replace(microsecond=int(fraction))
