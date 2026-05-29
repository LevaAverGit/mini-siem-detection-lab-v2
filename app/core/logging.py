import logging
import sys

from app.core.config import settings


def configure_logging() -> None:
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt='{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "msg": "%(message)s"}',
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    logging.basicConfig(level=level, handlers=[handler])


logger = logging.getLogger("siem")
