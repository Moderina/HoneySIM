import argparse
import socket
from concurrent.futures import ThreadPoolExecutor

DEFAULT_PORTS = "21,22,23,25,80,110,139,443,445,1433,3306,3389,5432,5900,6379,8080,8443"


def parse_ports(spec: str) -> list[int]:
    ports = []
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            ports.extend(range(int(lo), int(hi) + 1))
        elif part.strip():
            ports.append(int(part))
    return ports


def probe(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="honeypot")
    parser.add_argument("--ports", default=DEFAULT_PORTS, help="e.g. 21,22,80 or 1-1024")
    parser.add_argument("--timeout", type=float, default=1.0)
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    with ThreadPoolExecutor(max_workers=50) as pool:
        results = pool.map(lambda p: (p, probe(args.host, p, args.timeout)), ports)
        open_ports = [p for p, is_open in results if is_open]

    print(f"Scanned {len(ports)} ports on {args.host}")
    print(f"Open: {', '.join(map(str, open_ports)) or 'none'}")


if __name__ == "__main__":
    main()
