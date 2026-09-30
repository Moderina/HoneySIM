import logging
import os
import socket
import threading

from honeypot.common import create_listener, log_event, serve_tcp

log = logging.getLogger("honeypot.tcp")

HOST = os.environ.get("TCP_HOST", "0.0.0.0")
PORTS = [int(p) for p in os.environ.get(
    "TCP_PORTS", "21,23,25,110,443,445,1433,3306,3389,5432,5900,6379").split(",") if p.strip()]
    
READ_TIMEOUT = float(os.environ.get("TCP_READ_TIMEOUT", "3"))
MAX_PAYLOAD_LOGGED = 512

SERVICES = {
    21: "FTP", 23: "TELNET", 25: "SMTP", 110: "POP3", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 3306: "MYSQL", 3389: "RDP", 5432: "POSTGRESQL", 5900: "VNC", 6379: "REDIS",
}
BANNERS = {
    21: b"220 (vsFTPd 3.0.5)\r\n",
    23: b"\r\nUbuntu 22.04.4 LTS\r\nlogin: ",
    25: b"220 mail.localdomain ESMTP Postfix (Ubuntu)\r\n",
    110: b"+OK Dovecot (Ubuntu) ready.\r\n",
    5900: b"RFB 003.008\n",
}


def handle_connection(client: socket.socket, addr, service_port: int) -> None:
    dst_ip, dst_port = client.getsockname()[:2]
    payload = b""
    try:
        banner = BANNERS.get(service_port)
        if banner:
            client.sendall(banner)
        client.settimeout(READ_TIMEOUT)
        payload = client.recv(1024)
    except OSError:
        pass  

    service = SERVICES.get(service_port, "UNKNOWN")
    log_event({
        "protocol": "TCP",
        "service": service,
        "source_ip": addr[0],
        "source_port": addr[1],
        "destination_ip": dst_ip,
        "destination_port": dst_port,
        "event_type": "tcp_connection",
        "payload": payload.decode("utf-8", "backslashreplace")[:MAX_PAYLOAD_LOGGED],
        "message": f"Connection to {service} port {dst_port}",
    })


def serve_port(sock: socket.socket, service_port: int) -> None:
    serve_tcp(sock, lambda client, addr: handle_connection(client, addr, service_port))


def start(host: str = HOST, ports: list[int] = PORTS) -> list[threading.Thread]:
    threads = []
    for port in ports:
        sock = create_listener(host, port)
        t = threading.Thread(target=serve_port, args=(sock, port), daemon=True, name=f"tcp-{port}")
        t.start()
        threads.append(t)
    return threads


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    start()
    log.info("decoy TCP ports listening on %s: %s", HOST, PORTS)
    threading.Event().wait()
