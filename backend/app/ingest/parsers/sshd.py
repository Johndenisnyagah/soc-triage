"""Linux sshd authentication events carried over syslog.

Port of the original LogLens parser, with three fixes:
  * real tz-aware datetimes instead of "May  5 02:10:11" strings
  * hostname extracted from the syslog header instead of assumed
  * year/timezone supplied by ParseContext (syslog carries neither)
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Iterator

from ..base import BaseParser, ParseContext, register
from ..schema import ActorType, Category, NormalizedEvent, Outcome, SourceType

# May  5 02:10:11 webserver01 sshd[1234]: Failed password for root from 1.2.3.4 port 54321 ssh2
_SYSLOG_HEADER = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

_PORT = r"(?:\s+port\s+(?P<port>\d+))?"
_MESSAGE_PATTERNS: list[tuple[re.Pattern[str], str, Outcome, bool]] = [
    # (pattern, action, outcome, invalid_user)  -- order matters within this
    # list only; the "invalid user" variant must precede the generic one.
    (
        re.compile(
            rf"Failed password for invalid user (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+){_PORT}"
        ),
        "login",
        Outcome.FAILURE,
        True,
    ),
    (
        re.compile(
            rf"Failed password for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+){_PORT}"
        ),
        "login",
        Outcome.FAILURE,
        False,
    ),
    (
        re.compile(rf"Invalid user (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+){_PORT}"),
        "login",
        Outcome.FAILURE,
        True,
    ),
    (
        re.compile(
            r"Accepted (?P<method>password|publickey|keyboard-interactive) for "
            rf"(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+){_PORT}"
        ),
        "login",
        Outcome.SUCCESS,
        False,
    ),
]

_MONTHS = {
    m: i
    for i, m in enumerate(
        "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1
    )
}


@register
class SshdSyslogParser(BaseParser):
    source_type = SourceType.SYSLOG_SSHD

    @classmethod
    def sniff(cls, sample: str) -> float:
        lines = [ln for ln in sample.splitlines() if ln.strip()]
        if not lines:
            return 0.0
        header_hits = sum(1 for ln in lines if _SYSLOG_HEADER.match(ln))
        sshd_hits = sum(1 for ln in lines if "sshd[" in ln or "sshd:" in ln)
        if not header_hits:
            return 0.0
        # Syslog shape alone is weak evidence; sshd process name confirms it.
        return min(1.0, 0.4 * (header_hits / len(lines)) + 0.6 * (sshd_hits / len(lines)))

    def parse(
        self, content: str, ctx: ParseContext
    ) -> Iterator[NormalizedEvent]:
        for line_no, raw_line in enumerate(content.splitlines(), start=1):
            ctx.stats.lines_read += 1
            line = raw_line.strip()
            if not line:
                continue

            header = _SYSLOG_HEADER.match(line)
            if not header:
                ctx.stats.lines_skipped += 1
                continue

            message = header.group("msg")
            for pattern, action, outcome, invalid_user in _MESSAGE_PATTERNS:
                match = pattern.search(message)
                if not match:
                    continue

                port = match.groupdict().get("port")
                pid = header.group("pid")
                yield NormalizedEvent(
                    source_type=self.source_type,
                    raw=line,
                    # Separates concurrent connections that share a one-second
                    # syslog timestamp. Empty sides rather than the string
                    # "None" when sshd omits one.
                    source_event_id=(
                        f"{pid or ''}:{port or ''}" if (pid or port) else None
                    ),
                    timestamp=self._timestamp(header, ctx, line_no),
                    category=Category.AUTHENTICATION,
                    action=action,
                    outcome=outcome,
                    actor_name=match.group("user"),
                    actor_type=ActorType.USER,
                    source_ip=match.group("ip"),
                    source_port=int(port) if port else None,
                    host=header.group("host") or ctx.default_host,
                    target_resource="sshd",
                    extra={
                        "service": header.group("proc"),
                        "pid": header.group("pid"),
                        "invalid_user": invalid_user,
                        "auth_method": match.groupdict().get("method"),
                    },
                )
                ctx.stats.events_emitted += 1
                break
            else:
                # Recognised syslog line, but not an auth event we model.
                ctx.stats.lines_skipped += 1

    def _timestamp(
        self, header: re.Match[str], ctx: ParseContext, line_no: int
    ) -> datetime | None:
        try:
            hour, minute, second = (int(p) for p in header.group("time").split(":"))
            return datetime(
                year=ctx.default_year,
                month=_MONTHS[header.group("mon")],
                day=int(header.group("day")),
                hour=hour,
                minute=minute,
                second=second,
                tzinfo=ctx.assume_tz,
            )
        except (KeyError, ValueError) as exc:
            ctx.stats.record_error(line_no, f"bad timestamp: {exc}", header.group(0))
            return None
