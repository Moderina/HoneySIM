from datetime import datetime, timezone
from typing import Annotated, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, PlainSerializer

from database.models import ALERT_STATUSES


def to_utc_iso(dt: datetime) -> str:
    return dt.replace(tzinfo=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def to_naive_utc(dt: datetime | None) -> datetime | None:
    if dt is None or dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


UTCDateTime = Annotated[datetime, PlainSerializer(to_utc_iso, return_type=str)]
AlertStatus = Literal[ALERT_STATUSES] 

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    total: int
    limit: int
    offset: int
    items: list[T]


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: UTCDateTime
    source_ip: str
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    protocol: str
    event_type: str
    severity: str
    username: str | None
    password: str | None
    message: str | None
    details: dict


class EventDetail(EventOut):
    raw_log: str
    alert_ids: list[int]


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: int
    timestamp: UTCDateTime
    type: str = Field(validation_alias="alert_type")
    severity: str
    source_ip: str
    description: str
    status: str
    first_seen: UTCDateTime
    last_seen: UTCDateTime
    event_count: int
    updated_at: UTCDateTime


class AlertDetail(AlertOut):
    evidence: dict
    events: list[EventOut] 


class AlertUpdate(BaseModel):
    status: AlertStatus


class TimelineBucket(BaseModel):
    start: UTCDateTime
    events: int
    alerts: int


class Timeline(BaseModel):
    range_minutes: int
    bucket_minutes: int
    buckets: list[TimelineBucket]


class Totals(BaseModel):
    events: int
    alerts: int
    open_alerts: int
    high_alerts: int
    hosts: int
    active_hosts_24h: int
    rejected_logs: int


class Statistics(BaseModel):
    totals: Totals
    alerts_by_type: dict[str, int]
    alerts_by_severity: dict[str, int]
    alerts_by_status: dict[str, int]
    events_by_protocol: dict[str, int]
    events_by_type: dict[str, int]
    timeline: Timeline


class TopIp(BaseModel):
    ip: str
    event_count: int
    alerts: int
    high_alerts: int
    first_seen: UTCDateTime
    last_seen: UTCDateTime
