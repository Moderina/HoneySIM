from datetime import datetime

from sqlalchemy import JSON, Column, ForeignKey, Index, String, Table, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

ALERT_STATUSES = ("OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE")
ACTIVE_ALERT_STATUSES = ("OPEN", "INVESTIGATING")


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(index=True)
    source_ip: Mapped[str] = mapped_column(String(45))
    source_port: Mapped[int | None]
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    destination_port: Mapped[int | None]
    protocol: Mapped[str] = mapped_column(String(16))
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(10))
    username: Mapped[str | None] = mapped_column(String(255))
    password: Mapped[str | None] = mapped_column(String(255))
    message: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    raw_log: Mapped[str] = mapped_column(Text)

    __table_args__ = (Index("ix_events_source_ip_timestamp", "source_ip", "timestamp"),)


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True)
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    event_count: Mapped[int] = mapped_column(default=0)


alert_events = Table(
    Base.metadata,
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", ForeignKey("events.id", ondelete="CASCADE"), primary_key=True),
)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(index=True) 
    alert_type: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(10))
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="OPEN", index=True)
    first_seen: Mapped[datetime] 
    last_seen: Mapped[datetime]
    event_count: Mapped[int] = mapped_column(default=0)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime]

    events: Mapped[list[Event]] = relationship(secondary=alert_events, order_by=Event.timestamp)


class RejectedLog(Base):
    __tablename__ = "rejected_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    received_at: Mapped[datetime]
    source: Mapped[str] = mapped_column(String(255))
    raw_log: Mapped[str] = mapped_column(Text)
    error: Mapped[str] = mapped_column(Text)


class CollectorState(Base):
    __tablename__ = "collector_state"

    path: Mapped[str] = mapped_column(String(1024), primary_key=True)
    inode: Mapped[int] = mapped_column(default=0)
    offset: Mapped[int] = mapped_column(default=0)
    updated_at: Mapped[datetime]
