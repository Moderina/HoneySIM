import html
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from honeypot.common import log_event

log = logging.getLogger("honeypot.http")

HOST = os.environ.get("HTTP_HOST", "0.0.0.0")
PORT = int(os.environ.get("HTTP_PORT", "80"))
SERVER_HEADER = os.environ.get("HTTP_SERVER_HEADER", "Apache/2.4.52 (Ubuntu)")
MAX_BODY_READ = 64 * 1024
MAX_BODY_LOGGED = 2048

LOGIN_PATHS = {"/", "/login", "/admin", "/admin/login", "/administrator", "/wp-login.php"}
USERNAME_FIELDS = ("username", "user", "login", "log", "email")
PASSWORD_FIELDS = ("password", "pass", "passwd", "pwd")

LOGIN_PAGE = """<!DOCTYPE html>
<html><head><title>Admin Panel - Login</title>
<style>body{{font-family:sans-serif;background:#f0f2f5}}form{{width:300px;margin:120px auto;
background:#fff;padding:24px;border-radius:6px}}input{{width:100%;margin:6px 0;padding:8px}}
.err{{color:#c00}}</style></head>
<body><form method="post" action="/login"><h2>Admin Panel</h2>{error}
<input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password">
<input type="submit" value="Sign in"></form></body></html>
"""
LOGIN_ERROR = '<p class="err">Invalid username or password.</p>'

ROBOTS_TXT = "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /config\n"

NOT_FOUND_PAGE = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head><body>
<h1>Not Found</h1><p>The requested URL {path} was not found on this server.</p>
<hr><address>{server} Server at {host} Port 80</address></body></html>
"""


def extract_credentials(body: bytes) -> dict:
    fields = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
    creds = {}
    for key, value in ((k.lower(), v[0]) for k, v in fields.items()):
        if key in USERNAME_FIELDS and "username" not in creds:
            creds["username"] = value
        elif key in PASSWORD_FIELDS and "password" not in creds:
            creds["password"] = value
    return creds


class HoneypotHandler(BaseHTTPRequestHandler):
    timeout = 10

    def version_string(self):
        return SERVER_HEADER

    # ======================= routing =====================================

    def do_GET(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_PATCH(self):
        self._handle()

    def do_OPTIONS(self):
        self._handle()

    def _handle(self):
        self._extra = {}
        body = self._read_body()
        route = urlsplit(self.path).path

        if self.command == "POST" and route in LOGIN_PATHS:
            creds = extract_credentials(body)
            if creds:
                self._extra.update(creds, event_type="http_login_failed")
            self._send(200, LOGIN_PAGE.format(error=LOGIN_ERROR))
        elif self.command in ("GET", "HEAD") and route in LOGIN_PATHS:
            self._send(200, LOGIN_PAGE.format(error=""))
        elif self.command in ("GET", "HEAD") and route == "/robots.txt":
            self._send(200, ROBOTS_TXT, "text/plain")
        elif self.command in ("GET", "HEAD", "POST"):
            page = NOT_FOUND_PAGE.format(path=html.escape(route), server=SERVER_HEADER,
                                         host=html.escape(self.headers.get("Host", "localhost")))
            self._send(404, page)
        else:
            self._send(405, "Method Not Allowed", "text/plain")

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        body = self.rfile.read(min(max(length, 0), MAX_BODY_READ)) if length else b""
        if body:
            self._extra["body"] = body.decode("utf-8", "replace")[:MAX_BODY_LOGGED]
        return body

    def _send(self, code: int, text: str, content_type: str = "text/html") -> None:
        data = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    # =========================== logging ======================================

    def handle(self):
        self._responded = False
        super().handle()
        if not self._responded:
            self._log_base({
                "event_type": "http_no_request",
                "message": "Connection closed without an HTTP request",
            })

    def _log_base(self, fields: dict) -> None:
        dst_ip, dst_port = self.connection.getsockname()[:2]
        log_event({
            "protocol": "HTTP",
            "source_ip": self.client_address[0],
            "source_port": self.client_address[1],
            "destination_ip": dst_ip,
            "destination_port": dst_port,
            **fields,
        })

    def log_request(self, code="-", size="-"):
        self._responded = True
        headers = dict(self.headers.items()) if getattr(self, "headers", None) else {}
        extra = dict(getattr(self, "_extra", None) or {})
        event_type = extra.pop("event_type", "http_request")
        method = getattr(self, "command", None) or None
        path = getattr(self, "path", None)
        try:
            status = int(code) 
        except (TypeError, ValueError):
            status = None
        self._log_base({
            "event_type": event_type,
            "method": method,
            "path": path,
            "request_line": (getattr(self, "requestline", "") or "")[:1024],
            "status": status,
            "user_agent": headers.get("User-Agent"),
            "headers": headers,
            **extra,
            "message": f"{method or '?'} {path or '?'} -> {status}",
        })

    def log_message(self, format, *args):
        pass 


class HoneypotHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def create_server(host: str = HOST, port: int = PORT) -> HoneypotHTTPServer:
    return HoneypotHTTPServer((host, port), HoneypotHandler)


def main() -> None:
    server = create_server()
    log.info("HTTP honeypot listening on %s:%d", HOST, PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
