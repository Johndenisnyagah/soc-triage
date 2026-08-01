"""POST /api/ingest -- upload a log file, parse it, persist the events.

Two things here are deliberate and easy to "optimise" into bugs:

1. Persistence uses `session.add_all()`, never `bulk_save_objects()`. Bulk ops
   bypass the ORM unit of work, so the `entity_links` cascade on each Event
   would be silently dropped and `event_entities` would stay empty -- taking
   cross-source correlation with it, with no error raised.

2. The parser generator is iterated and flushed in batches; `list()` is never
   called on it. Note this is *not* fully streaming: `parse()` takes the whole
   content string, so the file is already resident in memory. Batching only
   avoids a second full copy as ORM objects, and keeps the session identity map
   from growing without bound.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.ingest.base import ParseContext, registered_parsers, select_parser
from app.models import Event, Ingest

router = APIRouter(prefix="/api", tags=["ingest"])

#: Events per flush. Large enough that flush overhead is amortised, small
#: enough that the identity map stays bounded on a big CloudTrail export.
BATCH_SIZE = 500

#: Ceiling on a single upload. This bounds what we decode into a Python str
#: and hold for the length of the request -- it is NOT a transport-level
#: limit. Starlette has already spooled the body (to disk past its own
#: threshold) by the time we see it, so a real defence belongs at the reverse
#: proxy. This stops a large file from becoming a large in-process string.
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))


class ParseErrorOut(BaseModel):
    line_no: int
    reason: str
    excerpt: str


class ParseStatsOut(BaseModel):
    lines_read: int
    events_emitted: int
    lines_skipped: int
    errors: list[ParseErrorOut]


class IngestResponse(BaseModel):
    ingest_id: int
    filename: str | None
    source_type: str
    detected_confidence: float
    events_persisted: int
    duplicates_skipped: int
    stats: ParseStatsOut


def _too_large(size: int) -> HTTPException:
    return HTTPException(
        status_code=413,
        detail={
            "error": "upload too large",
            "message": (
                f"File is {size} bytes; the limit is {MAX_UPLOAD_BYTES}. Split "
                "the export, or raise MAX_UPLOAD_BYTES."
            ),
            "max_upload_bytes": MAX_UPLOAD_BYTES,
            "received_bytes": size,
        },
    )


@router.post("/ingest", response_model=IngestResponse, status_code=201)
async def ingest_file(
    file: UploadFile = File(...),
    default_year: int | None = Form(None),
    default_host: str | None = Form(None),
    db: Session = Depends(get_db),
) -> IngestResponse:
    # Starlette populates .size for spooled uploads; check it before reading
    # so an oversized file is rejected without being pulled into memory.
    if file.size is not None and file.size > MAX_UPLOAD_BYTES:
        raise _too_large(file.size)

    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:  # .size absent or understated
        raise _too_large(len(raw))

    # errors="replace" rather than strict: a single bad byte in a 200 MB log
    # must not cost the operator the whole upload.
    content = raw.decode("utf-8", errors="replace")

    parser_cls, confidence = select_parser(content)
    if parser_cls is None:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "unrecognised log format",
                "message": (
                    "No parser recognised this file with enough confidence to "
                    "parse it safely. Guessing would produce garbage events, so "
                    "nothing was ingested."
                ),
                "best_confidence": round(confidence, 3),
                "min_confidence": 0.3,
                "supported_formats": [
                    str(p.source_type) for p in registered_parsers()
                ],
            },
        )

    ctx_kwargs: dict = {"filename": file.filename}
    if default_year is not None:
        ctx_kwargs["default_year"] = default_year
    if default_host is not None:
        ctx_kwargs["default_host"] = default_host
    ctx = ParseContext(**ctx_kwargs)

    ingest = Ingest(
        filename=file.filename,
        source_type=str(parser_cls.source_type),
        detected_confidence=confidence,
    )
    db.add(ingest)
    db.flush()  # assigns ingest.id, needed by Event.from_normalized

    parser = parser_cls()
    seen: set[str] = set()
    batch: list[Event] = []
    persisted = 0
    duplicates = 0

    def _flush() -> None:
        nonlocal persisted, duplicates
        if not batch:
            return

        # uq_event_dedup is global, so a re-uploaded file collides with the
        # events the *previous* ingest already wrote. Checking a batch at a
        # time keeps this bounded -- one IN query per 500 rows rather than
        # loading every hash in the table.
        already = set(
            db.scalars(
                select(Event.dedup_hash).where(
                    Event.dedup_hash.in_([e.dedup_hash for e in batch])
                )
            )
        )
        fresh = [e for e in batch if e.dedup_hash not in already]
        duplicates += len(batch) - len(fresh)

        if fresh:
            db.add_all(fresh)
            db.flush()
            persisted += len(fresh)
        batch.clear()

    for normalized in parser.parse(content, ctx):
        # Within a single run the batch hasn't been flushed yet, so the DB
        # check above cannot see these -- hence the in-memory set as well.
        fingerprint = normalized.dedup_hash()
        if fingerprint in seen:
            duplicates += 1
            continue
        seen.add(fingerprint)

        batch.append(Event.from_normalized(normalized, ingest.id))
        if len(batch) >= BATCH_SIZE:
            _flush()

    _flush()

    ingest.lines_read = ctx.stats.lines_read
    ingest.events_emitted = ctx.stats.events_emitted
    ingest.lines_skipped = ctx.stats.lines_skipped
    db.commit()

    return IngestResponse(
        ingest_id=ingest.id,
        filename=ingest.filename,
        source_type=ingest.source_type,
        detected_confidence=confidence,
        events_persisted=persisted,
        duplicates_skipped=duplicates,
        stats=ParseStatsOut(
            lines_read=ctx.stats.lines_read,
            events_emitted=ctx.stats.events_emitted,
            lines_skipped=ctx.stats.lines_skipped,
            errors=[
                ParseErrorOut(
                    line_no=e.line_no, reason=e.reason, excerpt=e.excerpt
                )
                for e in ctx.stats.errors
            ],
        ),
    )
