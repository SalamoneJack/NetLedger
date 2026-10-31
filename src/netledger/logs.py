"""Logging: Rich console output for people, JSON lines for log pipelines, optional rotating file."""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from pathlib import Path

NOISY_LOGGERS = ("paramiko", "netmiko", "ncclient", "urllib3", "pyeapi", "jnpr", "napalm", "scp", "requests")
PLAIN_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: str = "INFO", fmt: str = "auto", file: str | None = None) -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    numeric = logging.getLevelName(str(level).upper())
    root.setLevel(numeric if isinstance(numeric, int) else logging.INFO)

    interactive = sys.stderr.isatty()
    if fmt == "json" or (fmt == "auto" and not interactive and os.environ.get("KUBERNETES_SERVICE_HOST")):
        handler: logging.Handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JsonFormatter())
    elif fmt != "text" and interactive:
        from rich.console import Console
        from rich.logging import RichHandler

        handler = RichHandler(console=Console(stderr=True), show_path=False, markup=False, rich_tracebacks=True, log_time_format="[%X]")
    else:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(PLAIN_FORMAT))
    root.addHandler(handler)

    if file:
        path = Path(file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(PLAIN_FORMAT))
        root.addHandler(file_handler)

    library_level = logging.DEBUG if os.environ.get("NETLEDGER_DEBUG_LIBS") else logging.WARNING
    for name in NOISY_LOGGERS:
        logging.getLogger(name).setLevel(library_level)
