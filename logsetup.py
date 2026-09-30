import logging
import os


def setup_logging(service: str) -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format=f"%(asctime)s %(levelname)s {service} [%(name)s] %(message)s",
    )
