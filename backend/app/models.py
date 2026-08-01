"""ORM models.

`Event` and `EventEntity` came from models_event.py, a staging file written
before database.py existed; they are folded in here unchanged in substance and
that file is gone. `Ingest` is new -- `Event.ingest_id` carried a ForeignKey to
"ingests.id" with no table behind it.

Key changes from the original LogLens `Event`:
  * timestamp is a real DateTime, not a String -- time-window correlation
    was impossible before
  * category/action/outcome triple replaces the flat event_type enum
  * entity_keys is its own table so cross-source correlation can index it
  * dedup_hash lets re-ingesting the same file be idempotent
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Ingest(Base):
    """One upload. Owns the events parsed out of it.

    The three counters mirror `ingest.base.ParseStats` so the parse outcome
    survives the request -- "we emitted 412 events and skipped 9 lines" has to
    be answerable later, not just in the upload response.
    """

    __tablename__ = "ingests"

    id = Column(Integer, primary_key=True)

    filename = Column(String(512), nullable=True)
    source_type = Column(String(32), nullable=False, index=True)
    detected_confidence = Column(Float, nullable=False)
    uploaded_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # ParseStats counters
    lines_read = Column(Integer, nullable=False, default=0)
    events_emitted = Column(Integer, nullable=False, default=0)
    lines_skipped = Column(Integer, nullable=False, default=0)

    events = relationship(
        "Event", back_populates="ingest", cascade="all, delete-orphan"
    )


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    ingest_id = Column(Integer, ForeignKey("ingests.id"), nullable=False, index=True)

    # provenance
    source_type = Column(String(32), nullable=False, index=True)
    raw = Column(Text, nullable=False)
    dedup_hash = Column(String(32), nullable=False)

    # when
    timestamp = Column(DateTime(timezone=True), nullable=True, index=True)
    ingested_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # what
    category = Column(String(32), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    outcome = Column(String(16), nullable=False, index=True)

    # who
    actor_name = Column(String(255), nullable=True, index=True)
    actor_id = Column(String(512), nullable=True)
    actor_type = Column(String(32), nullable=False, default="unknown")

    # from where
    source_ip = Column(String(45), nullable=True, index=True)  # 45 = max IPv6
    source_port = Column(Integer, nullable=True)
    user_agent = Column(Text, nullable=True)

    # to what
    host = Column(String(255), nullable=True, index=True)
    target_resource = Column(String(512), nullable=True)

    extra = Column(JSON, nullable=False, default=dict)

    ingest = relationship("Ingest", back_populates="events")
    entity_links = relationship(
        "EventEntity", back_populates="event", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Global, not scoped to ingest_id: re-uploading the same file must be
        # genuinely idempotent rather than producing a second copy of every
        # event under a new ingest.
        UniqueConstraint("dedup_hash", name="uq_event_dedup"),
        # The workhorse index: "failed auth from this IP in this window".
        Index("ix_event_triage", "category", "outcome", "source_ip", "timestamp"),
    )

    @classmethod
    def from_normalized(cls, event, ingest_id: int) -> "Event":
        return cls(
            ingest_id=ingest_id,
            source_type=str(event.source_type),
            raw=event.raw,
            dedup_hash=event.dedup_hash(),
            timestamp=event.timestamp,
            category=str(event.category),
            action=event.action,
            outcome=str(event.outcome),
            actor_name=event.actor_name,
            actor_id=event.actor_id,
            actor_type=str(event.actor_type),
            source_ip=event.source_ip,
            source_port=event.source_port,
            user_agent=event.user_agent,
            host=event.host,
            target_resource=event.target_resource,
            extra=event.extra,
            entity_links=[EventEntity(entity_key=k) for k in event.entity_keys()],
        )


class EventEntity(Base):
    """Many-to-many between events and the entities they mention.

    Separate table rather than a JSON array so correlation queries can use an
    index: "every event touching ip:203.0.113.5 in the last hour" is a single
    indexed lookup across all sources.
    """

    __tablename__ = "event_entities"

    id = Column(Integer, primary_key=True)
    event_id = Column(
        Integer, ForeignKey("events.id", ondelete="CASCADE"), nullable=False
    )
    entity_key = Column(String(320), nullable=False)

    event = relationship("Event", back_populates="entity_links")

    __table_args__ = (
        Index("ix_entity_lookup", "entity_key", "event_id"),
    )
