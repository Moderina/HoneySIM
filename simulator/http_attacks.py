import argparse
import http.client
from urllib.parse import urlencode

REQUESTS = [
    ("normal browsing", "GET", "/", None),
    ("robots.txt recon", "GET", "/robots.txt", None),
    ("login attempt", "POST", "/login", {"username": "admin", "password": "admin"}),
    ("login attempt", "POST", "/login", {"username": "root", "password": "123456"}),
    ("wordpress login", "POST", "/wp-login.php", {"log": "admin", "pwd": "password"}),
    ("path traversal", "GET", "/../../../../etc/passwd", None),
    ("encoded traversal", "GET", "/download?file=..%2F..%2F..%2Fetc%2Fpasswd", None),
    ("XSS", "GET", "/search?q=<script>alert(1)</script>", None),
    ("SQL injection", "GET", "/item?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", None),
    ("SQLi login bypass", "POST", "/login", {"username": "admin' OR '1'='1", "password": "x"}),
    ("sensitive file", "GET", "/.env", None),
    ("sensitive file", "GET", "/.git/config", None),
    ("admin probe", "GET", "/phpmyadmin/", None),
]


def send(host: str, port: int, method: str, path: str, form: dict | None) -> int:
    body = urlencode(form) if form else None
    headers = {"User-Agent": "HoneySIM-simulator/1.0"}
    if body:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers)
        return conn.getresponse().status
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="honeypot")
    parser.add_argument("--port", type=int, default=80)
    args = parser.parse_args()

    for label, method, path, form in REQUESTS:
        try:
            status = send(args.host, args.port, method, path, form)
        except OSError as exc:
            status = f"error: {exc}"
        print(f"{label:<20} {method:<5} {path:<70} -> {status}")


if __name__ == "__main__":
    main()
