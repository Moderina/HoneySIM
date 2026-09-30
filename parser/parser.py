import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import unquote_plus

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

EVENT_TYPES = {
    "ssh_connection": ("CONNECTION", "INFO"),
    "ssh_login_failed": ("LOGIN_FAILURE", "LOW"),
    "ssh_protocol_error": ("PROTOCOL_ERROR", "LOW"),
    "http_request": ("HTTP_REQUEST", "INFO"),
    "http_login_failed": ("LOGIN_FAILURE", "LOW"),
    "http_no_request": ("CONNECTION", "INFO"),
    "tcp_connection": ("CONNECTION", "INFO"),
}

COMMON_FIELDS = {
    "timestamp", "protocol", "service", "source_ip", "source_port", "destination_ip",
    "destination_port", "event_type", "username", "password", "message",
}


class ParseError(ValueError):
    pass


@dataclass
class NormalizedEvent:
    timestamp: datetime
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
    raw_log: str
    details: dict = field(default_factory=dict)


def parse_timestamp(value) -> datetime:
    if not isinstance(value, str):
        raise ParseError(f"timestamp must be a string, got {value!r}")
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ParseError(f"invalid timestamp {value!r}") from exc
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts


def parse_ip(value, field_name: str, required: bool) -> str | None:
    if value in (None, ""):
        if required:
            raise ParseError(f"missing {field_name}")
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ParseError(f"invalid {field_name} {value!r}") from exc


def parse_port(value, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        raise ParseError(f"invalid {field_name} {value!r}")
    return value


def decode_url(path: str, max_rounds: int = 3) -> str:
    for _ in range(max_rounds):
        decoded = unquote_plus(path)
        if decoded == path:
            break
        path = decoded
    return path


def optional_str(value) -> str | None:
    return None if value is None else str(value)


def parse_line(line: str) -> NormalizedEvent:
    raw_log = line.strip()
    try:
        raw = json.loads(raw_log)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ParseError("log entry is not a JSON object")

    raw_type = raw.get("event_type")
    if not isinstance(raw_type, str) or not raw_type:
        raise ParseError("missing event_type")
    if "timestamp" not in raw:
        raise ParseError("missing timestamp")
    event_type, severity = EVENT_TYPES.get(raw_type, (raw_type.upper(), "INFO"))

    protocol = raw.get("service") if raw.get("protocol") == "TCP" and raw.get("service") else raw.get("protocol")
    protocol = str(protocol or "UNKNOWN").upper()

    details = {k: v for k, v in raw.items() if k not in COMMON_FIELDS}
    details["original_event_type"] = raw_type
    if isinstance(details.get("path"), str):
        details["path_decoded"] = decode_url(details["path"])

    return NormalizedEvent(
        timestamp=parse_timestamp(raw["timestamp"]),
        source_ip=parse_ip(raw.get("source_ip"), "source_ip", required=True),
        source_port=parse_port(raw.get("source_port"), "source_port"),
        destination_ip=parse_ip(raw.get("destination_ip"), "destination_ip", required=False),
        destination_port=parse_port(raw.get("destination_port"), "destination_port"),
        protocol=protocol,
        event_type=event_type,
        severity=severity,
        username=optional_str(raw.get("username")),
        password=optional_str(raw.get("password")),
        message=optional_str(raw.get("message")),
        raw_log=raw_log,
        details=details,
    )
