import logging
import os
import threading

from honeypot import common, http_honeypot, ssh_honeypot, tcp_listener
from logsetup import setup_logging

log = logging.getLogger("honeypot")


def run_or_die(name: str, target) -> threading.Thread:
    def wrapper():
        try:
            target()
        except Exception:
            log.exception("service %s crashed", name)
        log.critical("service %s stopped - exiting so Docker can restart the container", name)
        os._exit(1)

    t = threading.Thread(target=wrapper, name=name, daemon=True)
    t.start()
    return t


def main() -> None:
    setup_logging("honeypot")
    tcp_listener.start()
    log.info("decoy TCP ports listening: %s", tcp_listener.PORTS)
    run_or_die("http", http_honeypot.main)
    run_or_die("ssh", ssh_honeypot.main)
    log.info("writing events to %s", common.LOG_PATH)
    threading.Event().wait()


if __name__ == "__main__":
    main()
