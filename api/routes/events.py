from datetime import datetime

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select

from api.deps import SessionDep
from api.schemas import EventDetail, EventOut, Page, to_naive_utc
from database.models import Event, alert_events

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=Page[EventOut])
def list_events(
    session: SessionDep,
    event_type: str | None = Query(None, description="e.g. LOGIN_FAILURE, CONNECTION, HTTP_REQUEST"),
    protocol: str | None = Query(None, description="e.g. SSH, HTTP, MYSQL"),
    source_ip: str | None = None,
    severity: str | None = None,
    since: datetime | None = Query(None, description="ISO 8601, e.g. 2026-09-29T10:00:00Z"),
    until: datetime | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    query = select(Event)
    if event_type:
        query = query.where(Event.event_type == event_type.upper())
    if protocol:
        query = query.where(Event.protocol == protocol.upper())
    if source_ip:
        query = query.where(Event.source_ip == source_ip)
    if severity:
        query = query.where(Event.severity == severity.upper())
    if since:
        query = query.where(Event.timestamp >= to_naive_utc(since))
    if until:
        query = query.where(Event.timestamp <= to_naive_utc(until))

    total = session.scalar(select(func.count()).select_from(query.subquery()))
    rows = session.scalars(query.order_by(Event.timestamp.desc(), Event.id.desc()).limit(limit).offset(offset))
    return Page(total=total, limit=limit, offset=offset, items=[EventOut.model_validate(e) for e in rows])


@router.get("/{event_id}", response_model=EventDetail)
def get_event(event_id: int, session: SessionDep):
    event = session.get(Event, event_id)
    if event is None:
        raise HTTPException(404, f"event {event_id} not found")
    alert_ids = session.scalars(
        select(alert_events.c.alert_id).where(alert_events.c.event_id == event_id).order_by(alert_events.c.alert_id)
    ).all()
    return EventDetail(**EventOut.model_validate(event).model_dump(), raw_log=event.raw_log, alert_ids=alert_ids)
