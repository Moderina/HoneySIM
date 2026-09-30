import os
import re
from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from database.models import Event
from parser.parser import decode_url


def env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


@dataclass
class Detection:
    events: list[Event] 


class Rule:
    alert_type: str
    severity: str

    def evaluate(self, session: Session, source_ip: str, batch: list[Event]) -> Detection | None:
        raise NotImplementedError

    def summarize(self, events: list[Event]) -> tuple[str, dict]:
        raise NotImplementedError

    def is_significant(self, events: list[Event]) -> bool:
        return bool(events)

    def select_new(self, linked: list[Event], candidates: list[Event]) -> list[Event]:
        return candidates


class DistinctValueMixin:

    def key(self, ev: Event):
        raise NotImplementedError

    def select_new(self, linked, candidates):
        seen = {self.key(e) for e in linked}
        picked = []
        for e in sorted(candidates, key=lambda e: (e.timestamp, e.id)):
            if self.key(e) not in seen:
                seen.add(self.key(e))
                picked.append(e)
        return picked


def span_seconds(events: list[Event]) -> int:
    return int((events[-1].timestamp - events[0].timestamp).total_seconds())


def duration_text(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds} second{'s' if seconds != 1 else ''}"
    parts = []
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60), ("s", 1)):
        if seconds >= size:
            parts.append(f"{seconds // size} {unit}")
            seconds %= size
    return " ".join(parts[:2])


def span_text(events: list[Event]) -> str:
    seconds = span_seconds(events)
    return "in under 1 second" if seconds < 1 else f"within {duration_text(seconds)}"


def first_seen_order(values) -> list:
    return list(dict.fromkeys(v for v in values if v is not None))



class WindowRule(Rule):
    window: timedelta
    threshold: int
    event_types: tuple[str, ...] | None = None

    def relevant(self, ev: Event) -> bool:
        return self.event_types is None or ev.event_type in self.event_types

    def measure(self, events: list[Event]) -> int:
        return len(events)

    def evaluate(self, session, source_ip, batch):
        new = [e for e in batch if self.relevant(e)]
        if not new:
            return None

        query = select(Event).where(
            Event.source_ip == source_ip,
            Event.timestamp >= min(e.timestamp for e in new) - self.window,
            Event.timestamp <= max(e.timestamp for e in new),
        )
        if self.event_types:
            query = query.where(Event.event_type.in_(self.event_types))
        candidates = sorted((e for e in session.scalars(query) if self.relevant(e)),
                            key=lambda e: (e.timestamp, e.id))
        times = [e.timestamp for e in candidates]
        new_ids = {e.id for e in new}

        triggered: dict[int, Event] = {}
        for end, ev in enumerate(candidates):
            if ev.id not in new_ids:
                continue
            window = candidates[bisect_left(times, ev.timestamp - self.window):end + 1]
            if self.measure(window) >= self.threshold:
                triggered.update((e.id, e) for e in window)
        return Detection(list(triggered.values())) if triggered else None

    def is_significant(self, events):
        return self.measure(events) >= self.threshold

    @property
    def window_seconds(self) -> int:
        return int(self.window.total_seconds())


class BruteForceRule(WindowRule):
    alert_type = "BRUTE_FORCE"
    severity = "HIGH"
    event_types = ("LOGIN_FAILURE",)
    window = timedelta(seconds=env_int("RULE_BRUTE_FORCE_WINDOW", 60))
    threshold = env_int("RULE_BRUTE_FORCE_THRESHOLD", 6) 

    def summarize(self, events):
        protocols = sorted({e.protocol for e in events})
        return (
            f"{len(events)} failed {'/'.join(protocols)} login attempts {span_text(events)}",
            {
                "rule": f">= {self.threshold} failed logins within {self.window_seconds} s",
                "attempts": len(events),
                "protocols": protocols,
                "target_ports": sorted({e.destination_port for e in events if e.destination_port}),
                "top_usernames": dict(Counter(e.username for e in events if e.username).most_common(10)),
                "top_passwords": dict(Counter(e.password for e in events if e.password).most_common(10)),
            },
        )


class UsernameEnumerationRule(DistinctValueMixin, WindowRule):
    alert_type = "USERNAME_ENUMERATION"
    severity = "MEDIUM"
    event_types = ("LOGIN_FAILURE",)
    window = timedelta(seconds=env_int("RULE_USERNAME_ENUM_WINDOW", 300))
    threshold = env_int("RULE_USERNAME_ENUM_THRESHOLD", 5)

    def key(self, ev):
        return ev.username

    def relevant(self, ev):
        return super().relevant(ev) and bool(ev.username)

    def measure(self, events):
        return len({e.username for e in events})

    def summarize(self, events):
        usernames = first_seen_order(e.username for e in events)
        shown = ", ".join(usernames[:10]) + (", ..." if len(usernames) > 10 else "")
        return (
            f"{len(usernames)} different usernames tried: {shown}",
            {
                "rule": f">= {self.threshold} distinct usernames within {self.window_seconds} s",
                "distinct_usernames": len(usernames),
                "usernames": usernames[:100],
                "protocols": sorted({e.protocol for e in events}),
            },
        )


class PortScanRule(DistinctValueMixin, WindowRule):
    alert_type = "PORT_SCAN"
    severity = "MEDIUM"
    window = timedelta(seconds=env_int("RULE_PORT_SCAN_WINDOW", 60))
    threshold = env_int("RULE_PORT_SCAN_THRESHOLD", 5)

    def key(self, ev):
        return ev.destination_port

    def relevant(self, ev):
        return ev.destination_port is not None

    def measure(self, events):
        return len({e.destination_port for e in events})

    def summarize(self, events):
        services = {}
        for e in events:
            services.setdefault(e.destination_port, e.protocol)
        ports = sorted(services)
        shown = ", ".join(map(str, ports[:20])) + (", ..." if len(ports) > 20 else "")
        return (
            f"Connections to {len(ports)} different ports {span_text(events)}: {shown}",
            {
                "rule": f">= {self.threshold} distinct ports within {self.window_seconds} s",
                "distinct_ports": len(ports),
                "ports": ports,
                "services": {str(p): s for p, s in sorted(services.items())},
            },
        )


class HighActivityRule(WindowRule):
    alert_type = "HIGH_ACTIVITY"
    severity = "MEDIUM"
    window = timedelta(seconds=env_int("RULE_HIGH_ACTIVITY_WINDOW", 300))
    threshold = env_int("RULE_HIGH_ACTIVITY_THRESHOLD", 101)

    def summarize(self, events):
        return (
            f"{len(events)} events {span_text(events)}",
            {
                "rule": f">= {self.threshold} events within {self.window_seconds} s",
                "events": len(events),
                "by_event_type": dict(Counter(e.event_type for e in events)),
                "by_protocol": dict(Counter(e.protocol for e in events)),
            },
        )



WEB_ATTACK_PATTERNS = {
    "PATH_TRAVERSAL": [r"\.\./", r"\.\.\\", r"/etc/(passwd|shadow|hosts)\b", r"\b(boot|win)\.ini\b"],
    "XSS": [r"<\s*script", r"javascript\s*:", r"\bon(error|load|mouseover|focus)\s*=", r"<\s*(img|svg|iframe)\b"],
    "SQL_INJECTION": [
        r"\bunion\b(\s|/\*.*?\*/)+(all\s+)?select\b",
        r"'\s*or\s*'[^']*'\s*=\s*'",         
        r"\bor\s+\d+\s*=\s*\d+",             
        r"\b(sleep|benchmark|pg_sleep)\s*\(",
        r"\binformation_schema\b",
        r"\bdrop\s+table\b",
        r"'\s*;?\s*--",
    ],
    "COMMAND_INJECTION": [
        r"(;|\|\|?|&&)\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|ping)\b",
        r"\$\([^)]*\)",
        r"`[^`]+`",
    ],
    "SENSITIVE_FILE": [r"/\.env\b", r"/\.git/", r"/\.htpasswd\b", r"/\.aws/", r"\bwp-config\.php\b", r"\bid_rsa\b"],
}
COMPILED_PATTERNS = {cat: [re.compile(p, re.IGNORECASE) for p in pats] for cat, pats in WEB_ATTACK_PATTERNS.items()}
SCANNER_USER_AGENT = re.compile(
    r"nikto|sqlmap|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|acunetix|hydra", re.IGNORECASE)


def classify_http(ev: Event) -> list[str]:
    if ev.protocol != "HTTP":
        return []
    d = ev.details or {}
    target = "\n".join([
        d.get("path_decoded") or decode_url(d.get("path") or d.get("request_line") or ""),
        decode_url(d.get("body") or ""),
    ])
    categories = [cat for cat, patterns in COMPILED_PATTERNS.items() if any(p.search(target) for p in patterns)]
    if SCANNER_USER_AGENT.search(d.get("user_agent") or ""):
        categories.append("SCANNER_TOOL")
    return categories


class WebAttackRule(Rule):
    alert_type = "WEB_ATTACK"
    severity = "HIGH"

    def evaluate(self, session, source_ip, batch):
        hits = [e for e in batch if classify_http(e)]
        return Detection(hits) if hits else None

    def summarize(self, events):
        categories = Counter(cat for e in events for cat in classify_http(e))
        samples = []
        for e in events[:10]:
            d = e.details or {}
            samples.append({"timestamp": e.timestamp.isoformat(timespec="milliseconds") + "Z", 
                            "method": d.get("method"),
                            "path": d.get("path_decoded") or d.get("path"),
                            "categories": classify_http(e)})
        return (
            f"{len(events)} malicious HTTP request(s): {', '.join(sorted(categories))}",
            {"requests": len(events), "categories": dict(categories), "samples": samples},
        )


def default_rules() -> list[Rule]:
    return [BruteForceRule(), UsernameEnumerationRule(), PortScanRule(), WebAttackRule(), HighActivityRule()]
