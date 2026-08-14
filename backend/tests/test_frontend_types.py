"""The generated TypeScript types must not drift from the response models.

`frontend/src/api/schema.ts` is generated from `app.openapi()`. Nothing forces a
developer who renames a Pydantic field to regenerate it, and the failure is
silent on the frontend side: TypeScript keeps compiling happily against the old
interface and the mismatch only surfaces as `undefined` at runtime. This test is
what makes the generated file trustworthy.
"""

from __future__ import annotations

import pytest

from scripts.generate_frontend_types import (
    OUTPUT_PATH,
    UnsupportedSchema,
    generate,
    ts_type,
)


def test_generated_types_are_current():
    assert OUTPUT_PATH.exists(), (
        f"{OUTPUT_PATH} is missing. Run: "
        "python scripts/generate_frontend_types.py"
    )
    assert OUTPUT_PATH.read_text(encoding="utf-8") == generate(), (
        "frontend/src/api/schema.ts is stale -- a response model changed without "
        "the types being regenerated. Run: "
        "python scripts/generate_frontend_types.py"
    )


def test_response_models_are_present():
    """The three shapes the UI actually renders."""
    rendered = generate()
    for name in ("IncidentSummary", "IncidentDetail", "TimelineEntry"):
        assert f"export interface {name} {{" in rendered


def test_nullable_timestamps_survive_generation():
    """`datetime | None` has to reach TypeScript as nullable.

    If this collapsed to `string`, every `first_seen` render would look safe to
    the compiler and throw on the first incident with no timestamped finding.
    """
    rendered = generate()
    assert "first_seen: string | null;" in rendered
    assert "last_seen: string | null;" in rendered


def test_enum_becomes_a_literal_union():
    """The severity filter is typed against the same values FastAPI validates."""
    assert (
        'export type SeverityName = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";'
        in generate()
    )


def test_unknown_construct_raises_rather_than_guessing():
    """The generator must refuse constructs it does not model.

    Emitting a plausible-but-wrong type is the failure mode this whole file
    exists to prevent, so silence here would defeat the point.
    """
    with pytest.raises(UnsupportedSchema):
        ts_type({"type": "integer", "enum": [1, 2]}, path="Fake.field")

    with pytest.raises(UnsupportedSchema):
        ts_type({"type": "array"}, path="Fake.field")

    with pytest.raises(UnsupportedSchema):
        ts_type({"$ref": "https://example.com/Other.json"}, path="Fake.field")
