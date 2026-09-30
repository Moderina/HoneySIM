import json
import logging
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from database.database import utc_now
from database.models import ACTIVE_ALERT_STATUSES, Alert, Event, alert_events
from detection.rules import Rule, default_rules

ALERT_LOG = os.environ.get("ALERT_LOG", "/data/logs/alerts.log")
MERGE_WINDOW = timedelta(minutes=int(os.environ.get("ALERT_MERGE_MINUTES", "15")))

log = logging.getLogger("detection")


@dataclass
class AlertChange:
    alert: Alert
    created: bool


class DetectionEngine:
    def __init__(self, rules: list[Rule] | None = None, merge_window: timedelta = MERGE_WINDOW):
        self.rules = default_rules() if rules is None else rules
        self.merge_window = merge_window

    def process(self, session: Session, events: list[Event]) -> list[AlertChange]:
        session.flush()  
        by_ip: dict[str, list[Event]] = defaultdict(list)
        for ev in events:
            by_ip[ev.source_ip].append(ev)

        changes = []
        for source_ip, ip_events in by_ip.items():
            for rule in self.rules:
                detection = rule.evaluate(session, source_ip, ip_events)
                change = detection and self._raise_alert(session, rule, source_ip, detection.events)
                if change:
                    changes.append(change)
        return changes

    def _raise_alert(self, session: Session, rule: Rule, source_ip: str,
                     events: list[Event]) -> AlertChange | None:
        first = min(e.timestamp for e in events)
        alert = session.scalar(
            select(Alert)
            .where(Alert.alert_type == rule.alert_type,
                   Alert.source_ip == source_ip,
                   Alert.status.in_(ACTIVE_ALERT_STATUSES),
                   Alert.last_seen >= first - self.merge_window)
            .order_by(Alert.id.desc())
            .limit(1)
        )
        now = utc_now()
        created = alert is None
        if created:
            covered = set(session.scalars(
                select(alert_events.c.event_id)
                .join(Alert, Alert.id == alert_events.c.alert_id)
                .where(Alert.alert_type == rule.alert_type, Alert.source_ip == source_ip,
                       alert_events.c.event_id.in_([e.id for e in events]))
            ))
            new_events = rule.select_new([], [e for e in events if e.id not in covered])
            if not new_events or not rule.is_significant(new_events):
                return None
            first = min(e.timestamp for e in new_events)
            alert = Alert(timestamp=now, alert_type=rule.alert_type, severity=rule.severity,
                          source_ip=source_ip, status="OPEN", first_seen=first, last_seen=first,
                          event_count=0, description="", evidence={}, updated_at=now)
            session.add(alert)
        else:
            known = {e.id for e in alert.events}
            new_events = rule.select_new(alert.events, [e for e in events if e.id not in known])
            if not new_events:
                return None

        alert.events.extend(new_events)
        linked = sorted(alert.events, key=lambda e: (e.timestamp, e.id))
        alert.first_seen = linked[0].timestamp
        alert.last_seen = linked[-1].timestamp
        alert.event_count = len(linked)
        alert.description, alert.evidence = rule.summarize(linked)
        alert.updated_at = now
        session.flush()
        return AlertChange(alert, created)


def alert_to_dict(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "timestamp": alert.timestamp.isoformat(),
        "type": alert.alert_type,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "description": alert.description,
        "status": alert.status,
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "event_count": alert.event_count,
    }


def notify(changes: list[AlertChange], path: str = ALERT_LOG) -> None:
    new_alerts = [alert_to_dict(c.alert) for c in changes if c.created]
    for c in changes:
        a = c.alert
        log.log(logging.WARNING if c.created else logging.INFO, "%s alert #%d %s %s %s: %s",
                "NEW" if c.created else "updated", a.id, a.severity, a.alert_type, a.source_ip, a.description)
    if new_alerts and path:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            for a in new_alerts:
                f.write(json.dumps(a, ensure_ascii=False) + "\n")
