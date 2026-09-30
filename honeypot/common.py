import json
import logging
import os
import socket
import threading
from datetime import datetime, timezone
from typing import Callable

LOG_PATH = os.environ.get("HONEYPOT_LOG", "/data/logs/honeypot.log")

_write_lock = threading.Lock()
log = logging.getLogger("honeypot")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def log_event(event: dict, path: str | None = None) -> dict:
    record = {"timestamp": utc_now_iso(), **event}
    line = json.dumps(record, ensure_ascii=False)
    path = path or LOG_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _write_lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    print(line, flush=True)
    return record


def create_listener(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    return sock


def serve_tcp(sock: socket.socket, handler: Callable[[socket.socket, tuple], None],
              max_connections: int = 100) -> None:
    slots = threading.BoundedSemaphore(max_connections)

    def worker(client, addr):
        try:
            handler(client, addr)
        except Exception:
            log.exception("error while handling connection from %s:%s", *addr[:2])
        finally:
            client.close()
            slots.release()

    while True:
        try:
            client, addr = sock.accept()
        except OSError:
            return  # listener closed
        if not slots.acquire(blocking=False):
            client.close()
            continue
        threading.Thread(target=worker, args=(client, addr), daemon=True).start()
