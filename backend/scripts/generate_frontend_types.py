"""Generate `frontend/src/api/schema.ts` from the FastAPI OpenAPI document.

The frontend must not hand-write interfaces for the response models. A
hand-written `IncidentSummary` drifts the moment a field is renamed in
`api_incidents.py`, and it drifts *silently* -- TypeScript keeps compiling
against the stale shape and the mismatch only shows up as `undefined` in the
browser. Generating from `app.openapi()` makes the Pydantic models the single
source of truth for both sides.

Scope is deliberately narrow. This handles the JSON Schema subset FastAPI
actually emits for this app's models -- objects, arrays, `$ref`, `anyOf`
unions, string enums, primitives -- and raises `UnsupportedSchema` on anything
else. A generator that guessed at an unfamiliar construct would emit a
plausible type that is wrong, which is the exact failure it exists to prevent.
`tests/test_frontend_types.py` regenerates and diffs, so a model change that is
not accompanied by a regenerated file fails the suite.

    python scripts/generate_frontend_types.py          # write
    python scripts/generate_frontend_types.py --check  # verify, no write
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app.main import app  # noqa: E402

#: Written relative to the repo root so the script works from any cwd.
OUTPUT_PATH = (
    pathlib.Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "src"
    / "api"
    / "schema.ts"
)

HEADER = """/**
 * Generated from the FastAPI OpenAPI document. Do not edit by hand.
 *
 * Regenerate after changing any Pydantic response model in
 * `backend/app/api_incidents.py`:
 *
 *     cd backend && python scripts/generate_frontend_types.py
 *
 * `backend/tests/test_frontend_types.py` fails if this file is out of date.
 */
"""

_PRIMITIVES = {
    "string": "string",
    "integer": "number",
    "number": "number",
    "boolean": "boolean",
    "null": "null",
}


class UnsupportedSchema(Exception):
    """A construct this generator will not guess at. Extend it deliberately."""


def _ref_name(ref: str) -> str:
    prefix = "#/components/schemas/"
    if not ref.startswith(prefix):
        raise UnsupportedSchema(f"external or non-component $ref: {ref!r}")
    return ref[len(prefix) :]


def ts_type(schema: dict[str, Any], *, path: str) -> str:
    """Render one JSON Schema node as a TypeScript type expression."""
    if "$ref" in schema:
        return _ref_name(schema["$ref"])

    if "anyOf" in schema:
        parts = [ts_type(s, path=f"{path}.anyOf") for s in schema["anyOf"]]
        # Deduplicate while preserving order -- `anyOf: [string, null]` is by far
        # the common case and should read as `string | null`, not a set.
        seen: dict[str, None] = {}
        for part in parts:
            seen.setdefault(part, None)
        return " | ".join(seen)

    if "allOf" in schema:
        members = schema["allOf"]
        if len(members) != 1:
            raise UnsupportedSchema(f"{path}: allOf with {len(members)} members")
        return ts_type(members[0], path=f"{path}.allOf")

    if "enum" in schema:
        if schema.get("type") != "string":
            raise UnsupportedSchema(f"{path}: non-string enum")
        return " | ".join(f'"{v}"' for v in schema["enum"])

    declared = schema.get("type")

    if declared is None:
        # Pydantic emits a bare `{"title": "Input"}` for an untyped field.
        # `unknown` forces the consumer to narrow; `any` would silently opt the
        # whole call site out of checking.
        return "unknown"

    if declared == "array":
        items = schema.get("items")
        if items is None:
            raise UnsupportedSchema(f"{path}: array without items")
        inner = ts_type(items, path=f"{path}[]")
        # Unions need parenthesising before `[]` binds.
        return f"({inner})[]" if "|" in inner else f"{inner}[]"

    if declared == "object":
        if schema.get("properties"):
            raise UnsupportedSchema(f"{path}: inline object; give it its own model")
        return "Record<string, unknown>"

    if declared == "string" and schema.get("contentMediaType") == (
        "application/octet-stream"
    ):
        return "Blob"

    if declared in _PRIMITIVES:
        return _PRIMITIVES[declared]

    raise UnsupportedSchema(f"{path}: unhandled type {declared!r}")


def _docblock(text: str | None, indent: str) -> list[str]:
    if not text:
        return []
    lines = text.strip().splitlines()
    if len(lines) == 1:
        return [f"{indent}/** {lines[0]} */"]
    out = [f"{indent}/**"]
    out += [f"{indent} * {line}".rstrip() for line in lines]
    out.append(f"{indent} */")
    return out


def render_schema(name: str, schema: dict[str, Any]) -> str:
    """Render one component schema as an exported interface or type alias."""
    lines: list[str] = []
    lines += _docblock(schema.get("description"), "")

    if "enum" in schema:
        lines.append(f"export type {name} = {ts_type(schema, path=name)};")
        return "\n".join(lines)

    if schema.get("type") != "object":
        lines.append(f"export type {name} = {ts_type(schema, path=name)};")
        return "\n".join(lines)

    required = set(schema.get("required", []))
    lines.append(f"export interface {name} {{")
    for prop, prop_schema in schema.get("properties", {}).items():
        lines += _docblock(prop_schema.get("description"), "  ")
        optional = "" if prop in required else "?"
        rendered = ts_type(prop_schema, path=f"{name}.{prop}")
        lines.append(f"  {prop}{optional}: {rendered};")
    lines.append("}")
    return "\n".join(lines)


def generate() -> str:
    schemas = app.openapi()["components"]["schemas"]
    blocks = [render_schema(name, schemas[name]) for name in sorted(schemas)]
    return HEADER + "\n" + "\n\n".join(blocks) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the file on disk differs from what would be generated",
    )
    args = parser.parse_args()

    rendered = generate()

    if args.check:
        if not OUTPUT_PATH.exists():
            print(f"MISSING: {OUTPUT_PATH}", file=sys.stderr)
            return 1
        if OUTPUT_PATH.read_text(encoding="utf-8") != rendered:
            print(
                f"STALE: {OUTPUT_PATH} does not match the current response models.\n"
                "Run: python scripts/generate_frontend_types.py",
                file=sys.stderr,
            )
            return 1
        print(f"up to date: {OUTPUT_PATH}")
        return 0

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
