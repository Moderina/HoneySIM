import logging
import os
import time

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from database.database import init_db, make_engine, make_session_factory, utc_now
from database.models import CollectorState, Event, Host, RejectedLog
from detection.engine import AlertChange, DetectionEngine, notify
from logsetup import setup_logging
from parser.parser import NormalizedEvent, ParseError, parse_line

LOG_PATH = os.environ.get("HONEYPOT_LOG", "/data/logs/honeypot.log")
POLL_INTERVAL = float(os.environ.get("COLLECTOR_POLL_INTERVAL", "1"))
BATCH_SIZE = int(os.environ.get("COLLECTOR_BATCH_SIZE", "500"))

log = logging.getLogger("collector")


class Collector:
    def __init__(self, session_factory: sessionmaker[Session], path: str = LOG_PATH,
                 batch_size: int = BATCH_SIZE, detector: DetectionEngine | None = None,
                 alert_log: str | None = None):
        self.session_factory = session_factory
        self.path = path
        self.batch_size = batch_size
        self.detector = detector
        self.alert_log = alert_log

    def poll_once(self) -> int:
        try:
            stat = os.stat(self.path)
        except FileNotFoundError:
            return 0

        with self.session_factory() as session, session.begin():
            state = session.get(CollectorState, self.path)
            if state is None:
                state = CollectorState(path=self.path, inode=stat.st_ino, offset=0, updated_at=utc_now())
                session.add(state)
            elif stat.st_ino != state.inode or stat.st_size < state.offset:
                log.warning("log file %s was rotated or truncated - reading from the start", self.path)
                state.inode, state.offset = stat.st_ino, 0

            lines, new_offset = self._read_complete_lines(state.offset)
            if not lines:
                return 0

            events, rejected = self._store(session, lines)
            changes: list[AlertChange] = self.detector.process(session, events) if self.detector else []
            state.offset = new_offset
            state.updated_at = utc_now()

        log.info("processed %d lines: %d events stored, %d rejected", len(lines), len(events), rejected)
        if changes:
            notify(changes, self.alert_log)
        return len(lines)

    def _read_complete_lines(self, offset: int) -> tuple[list[bytes], int]:
        lines = []
        with open(self.path, "rb") as f:
            f.seek(offset)
            while len(lines) < self.batch_size:
                line = f.readline()
                if not line.endswith(b"\n"):
                    break 
                lines.append(line)
                offset += len(line)
        return lines, offset

    def _store(self, session: Session, lines: list[bytes]) -> tuple[list[Event], int]:
        hosts: dict[str, Host] = {}
        stored: list[Event] = []
        rejected = 0
        for raw in lines:
            text = raw.decode("utf-8", "replace").strip()
            if not text:
                continue
            try:
                parsed = parse_line(text)
            except ParseError as exc:
                session.add(RejectedLog(received_at=utc_now(), source=self.path, raw_log=text, error=str(exc)))
                log.warning("rejected log line: %s", exc)
                rejected += 1
                continue
            event = to_model(parsed)
            session.add(event)
            self._update_host(session, hosts, parsed)
            stored.append(event)
        return stored, rejected

    @staticmethod
    def _update_host(session: Session, cache: dict[str, Host], ev: NormalizedEvent) -> None:
        host = cache.get(ev.source_ip)
        if host is None:
            host = session.scalar(select(Host).where(Host.ip == ev.source_ip))
        if host is None:
            host = Host(ip=ev.source_ip, first_seen=ev.timestamp, last_seen=ev.timestamp, event_count=0)
            session.add(host)
        cache[ev.source_ip] = host
        host.first_seen = min(host.first_seen, ev.timestamp)
        host.last_seen = max(host.last_seen, ev.timestamp)
        host.event_count += 1

    def run_forever(self, poll_interval: float = POLL_INTERVAL) -> None:
        log.info("watching %s", self.path)
        while True:
            try:
                consumed = self.poll_once()
            except Exception:
                log.exception("collector error - retrying")
                consumed = 0
            if consumed < self.batch_size:
                time.sleep(poll_interval)


def to_model(ev: NormalizedEvent) -> Event:
    return Event(
        timestamp=ev.timestamp, source_ip=ev.source_ip, source_port=ev.source_port,
        destination_ip=ev.destination_ip, destination_port=ev.destination_port,
        protocol=ev.protocol, event_type=ev.event_type, severity=ev.severity,
        username=ev.username, password=ev.password, message=ev.message,
        details=ev.details, raw_log=ev.raw_log,
    )


def main() -> None:
    setup_logging("collector")
    engine = make_engine()
    init_db(engine)
    collector = Collector(make_session_factory(engine), detector=DetectionEngine(),
                          alert_log=os.environ.get("ALERT_LOG", "/data/logs/alerts.log"))
    collector.run_forever()


if __name__ == "__main__":
    main()
