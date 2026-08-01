from __future__ import annotations

from app.ingest import parsers  # noqa: F401 -- registers both parsers
from app.ingest.base import registered_parsers, select_parser
from app.ingest.parsers.cloudtrail import CloudTrailParser
from app.ingest.parsers.sshd import SshdSyslogParser


def test_registry_is_populated():
    """Guards the failure that started this: an empty parsers/__init__.py
    leaves the registry empty and every ingest reports 'unrecognised format'
    with no error anywhere."""
    assert set(registered_parsers()) == {SshdSyslogParser, CloudTrailParser}


def test_selects_sshd():
    content = (
        "May  5 02:10:11 webserver01 sshd[1234]: "
        "Failed password for root from 203.0.113.5 port 54321 ssh2"
    )
    parser_cls, confidence = select_parser(content)
    assert parser_cls is SshdSyslogParser
    assert confidence >= 0.3


def test_selects_cloudtrail():
    content = (
        '{"Records":[{"eventVersion":"1.08","userIdentity":{"type":"IAMUser"},'
        '"eventSource":"iam.amazonaws.com","awsRegion":"us-east-1",'
        '"eventName":"CreateUser"}]}'
    )
    parser_cls, confidence = select_parser(content)
    assert parser_cls is CloudTrailParser
    assert confidence >= 0.3


def test_below_floor_returns_none_and_the_score():
    """A lone CloudTrail marker scores 0.25 -- real evidence, but under the
    0.3 floor. We report the score rather than guessing and emitting garbage.
    """
    content = '{"eventVersion": "1.08", "somethingElse": true}'

    parser_cls, confidence = select_parser(content)

    assert parser_cls is None
    assert 0.0 < confidence < 0.3
    assert confidence == 0.25


def test_unrecognisable_content_scores_zero():
    parser_cls, confidence = select_parser(
        "the quick brown fox\njumped over the lazy dog\n"
    )
    assert parser_cls is None
    assert confidence == 0.0


def test_empty_content_returns_none():
    parser_cls, confidence = select_parser("   \n\n   ")
    assert parser_cls is None
    assert confidence == 0.0
