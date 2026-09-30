import logging

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select

from api.deps import SessionDep
from api.schemas import AlertDetail, AlertOut, AlertStatus, AlertUpdate, EventOut, Page
from database.database import utc_now
from database.models import Alert, Event, alert_events

router = APIRouter(prefix="/api/alerts", tags=["alerts"])
log = logging.getLogger("api")


def get_alert_or_404(session, alert_id: int) -> Alert:
    alert = session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(404, f"alert {alert_id} not found")
    return alert


@router.get("", response_model=Page[AlertOut])
def list_alerts(
    session: SessionDep,
    status: list[AlertStatus] | None = Query(None, description="repeatable: ?status=OPEN&status=INVESTIGATING"),
    severity: str | None = None,
    type: str | None = Query(None, description="e.g. BRUTE_FORCE, PORT_SCAN, WEB_ATTACK"),
    source_ip: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    query = select(Alert)
    if status:
        query = query.where(Alert.status.in_(status))
    if severity:
        query = query.where(Alert.severity == severity.upper())
    if type:
        query = query.where(Alert.alert_type == type.upper())
    if source_ip:
        query = query.where(Alert.source_ip == source_ip)

    total = session.scalar(select(func.count()).select_from(query.subquery()))
    rows = session.scalars(query.order_by(Alert.last_seen.desc(), Alert.id.desc()).limit(limit).offset(offset))
    return Page(total=total, limit=limit, offset=offset, items=[AlertOut.model_validate(a) for a in rows])


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: int, session: SessionDep,
              events_limit: int = Query(500, ge=0, le=5000, description="max timeline events returned")):
    alert = get_alert_or_404(session, alert_id)
    events = session.scalars(
        select(Event).join(alert_events, alert_events.c.event_id == Event.id)
        .where(alert_events.c.alert_id == alert_id)
        .order_by(Event.timestamp, Event.id)
        .limit(events_limit)
    )
    return AlertDetail(**AlertOut.model_validate(alert).model_dump(), evidence=alert.evidence,
                       events=[EventOut.model_validate(e) for e in events])


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(alert_id: int, update: AlertUpdate, session: SessionDep):
    alert = get_alert_or_404(session, alert_id)
    if alert.status != update.status:
        log.info("alert #%d status %s -> %s", alert.id, alert.status, update.status)
        alert.status = update.status
        alert.updated_at = utc_now()
        session.commit()
    return AlertOut.model_validate(alert)
