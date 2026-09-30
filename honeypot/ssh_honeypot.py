import logging
import os
import socket
import threading
import time

import paramiko

from honeypot.common import create_listener, log_event, serve_tcp

HOST = os.environ.get("SSH_HOST", "0.0.0.0")
PORT = int(os.environ.get("SSH_PORT", "22"))
HOST_KEY_PATH = os.environ.get("SSH_HOST_KEY", "/data/keys/ssh_host_rsa_key")
BANNER = os.environ.get("SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
SESSION_TIMEOUT = float(os.environ.get("SSH_SESSION_TIMEOUT", "60"))
MAX_AUTH_ATTEMPTS = int(os.environ.get("SSH_MAX_AUTH_ATTEMPTS", "6"))
MAX_CONNECTIONS = int(os.environ.get("SSH_MAX_CONNECTIONS", "100"))

logging.getLogger("paramiko").setLevel(logging.CRITICAL)
log = logging.getLogger("honeypot.ssh")


def load_host_key(path: str = HOST_KEY_PATH) -> paramiko.RSAKey:
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, conn_info: dict, transport: paramiko.Transport):
        self.conn_info = conn_info
        self.transport = transport
        self.attempts = 0

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.attempts += 1
        log_event({
            **self.conn_info,
            "event_type": "ssh_login_failed",
            "username": username,
            "password": password,
            "attempt": self.attempts,
            "client_version": self.transport.remote_version,
            "message": "Authentication failed",
        })
        if self.attempts >= MAX_AUTH_ATTEMPTS:
            threading.Timer(0.1, self.transport.close).start()
        return paramiko.AUTH_FAILED


def handle_connection(client: socket.socket, addr, host_key: paramiko.PKey) -> None:
    dst_ip, dst_port = client.getsockname()[:2]
    conn_info = {
        "protocol": "SSH",
        "source_ip": addr[0],
        "source_port": addr[1],
        "destination_ip": dst_ip,
        "destination_port": dst_port,
    }
    log_event({**conn_info, "event_type": "ssh_connection", "message": "New connection"})

    transport = paramiko.Transport(client)
    transport.local_version = BANNER
    transport.add_server_key(host_key)
    server = HoneypotServer(conn_info, transport)
    try:
        transport.start_server(server=server)
        deadline = time.monotonic() + SESSION_TIMEOUT
        while transport.is_active() and time.monotonic() < deadline:
            time.sleep(0.2)
    except (paramiko.SSHException, EOFError, OSError) as exc:
        log_event({
            **conn_info,
            "event_type": "ssh_protocol_error",
            "message": str(exc) or exc.__class__.__name__,
        })
    finally:
        transport.close()


def serve_forever(sock: socket.socket, host_key: paramiko.PKey) -> None:
    serve_tcp(sock, lambda client, addr: handle_connection(client, addr, host_key), MAX_CONNECTIONS)


def main() -> None:
    host_key = load_host_key()
    sock = create_listener(HOST, PORT)
    log.info("SSH honeypot listening on %s:%d", HOST, PORT)
    serve_forever(sock, host_key)


if __name__ == "__main__":
    main()
