from datetime import datetime, timedelta

from fastapi import APIRouter, Query
from sqlalchemy import Integer, case, cast, func, select
from sqlalchemy.orm import Session

from api.deps import SessionDep
from api.schemas import Statistics, Timeline, TimelineBucket, TopIp, Totals
from database.database import utc_now
from database.models import ACTIVE_ALERT_STATUSES, Alert, Event, Host, RejectedLog

router = APIRouter(prefix="/api", tags=["statistics"])

HIGH_SEVERITIES = ("HIGH", "CRITICAL")
BUCKET_SIZES = (1, 5, 15, 30, 60, 180, 360, 720, 1440) 
MAX_BUCKETS = 60


def count(session: Session, model, *where) -> int:
    return session.scalar(select(func.count()).select_from(model).where(*where))


def grouped(session: Session, column) -> dict[str, int]:
    rows = session.execute(select(column, func.count()).group_by(column).order_by(func.count().desc()))
    return {key: n for key, n in rows}


def epoch_seconds(session: Session, column):
    if session.get_bind().dialect.name == "sqlite":
        return cast(func.strftime("%s", column), Integer)
    return cast(func.extract("epoch", column), Integer)


def bucket_counts(session: Session, column, start: datetime, bucket_s: int) -> dict[int, int]:
    bucket = cast(epoch_seconds(session, column) / bucket_s, Integer).label("bucket")
    rows = session.execute(select(bucket, func.count()).where(column >= start).group_by(bucket))
    return {int(b): n for b, n in rows}


def build_timeline(session: Session, range_minutes: int) -> Timeline:
    bucket_min = next((b for b in BUCKET_SIZES if range_minutes / b <= MAX_BUCKETS), BUCKET_SIZES[-1])
    bucket_s = bucket_min * 60
    now = utc_now()
    epoch = datetime(1970, 1, 1)
    last = int((now - epoch).total_seconds()) // bucket_s
    first = last - range_minutes // bucket_min + 1
    start = epoch + timedelta(seconds=first * bucket_s)

    events = bucket_counts(session, Event.timestamp, start, bucket_s)
    alerts = bucket_counts(session, Alert.timestamp, start, bucket_s)
    buckets = [
        TimelineBucket(start=epoch + timedelta(seconds=i * bucket_s), events=events.get(i, 0), alerts=alerts.get(i, 0))
        for i in range(first, last + 1)
    ]
    return Timeline(range_minutes=range_minutes, bucket_minutes=bucket_min, buckets=buckets)


@router.get("/statistics", response_model=Statistics)
def statistics(session: SessionDep,
               range_minutes: int = Query(60, ge=5, le=10080, description="timeline range (max 7 days)")):
    totals = Totals(
        events=count(session, Event),
        alerts=count(session, Alert),
        open_alerts=count(session, Alert, Alert.status.in_(ACTIVE_ALERT_STATUSES)),
        high_alerts=count(session, Alert, Alert.severity.in_(HIGH_SEVERITIES)),
        hosts=count(session, Host),
        active_hosts_24h=count(session, Host, Host.last_seen >= utc_now() - timedelta(hours=24)),
        rejected_logs=count(session, RejectedLog),
    )
    return Statistics(
        totals=totals,
        alerts_by_type=grouped(session, Alert.alert_type),
        alerts_by_severity=grouped(session, Alert.severity),
        alerts_by_status=grouped(session, Alert.status),
        events_by_protocol=grouped(session, Event.protocol),
        events_by_type=grouped(session, Event.event_type),
        timeline=build_timeline(session, range_minutes),
    )


@router.get("/top-ips", response_model=list[TopIp])
def top_ips(session: SessionDep, limit: int = Query(10, ge=1, le=100)):
    per_ip = (
        select(Alert.source_ip,
               func.count().label("alerts"),
               func.sum(case((Alert.severity.in_(HIGH_SEVERITIES), 1), else_=0)).label("high_alerts"))
        .group_by(Alert.source_ip)
        .subquery()
    )
    rows = session.execute(
        select(Host, func.coalesce(per_ip.c.alerts, 0), func.coalesce(per_ip.c.high_alerts, 0))
        .outerjoin(per_ip, per_ip.c.source_ip == Host.ip)
        .order_by(Host.event_count.desc(), Host.ip)
        .limit(limit)
    )
    return [
        TopIp(ip=h.ip, event_count=h.event_count, alerts=alerts, high_alerts=high,
              first_seen=h.first_seen, last_seen=h.last_seen)
        for h, alerts, high in rows
    ]
