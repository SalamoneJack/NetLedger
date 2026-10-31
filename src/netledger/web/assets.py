"""Static assets (CSS/JS) shipped inside the package and served with content-hashed URLs."""

from __future__ import annotations

import hashlib
from functools import cache
from importlib import resources

TYPES = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}
NAMES = ("app.css", "app.js")


@cache
def _load(name: str) -> bytes:
    return (resources.files("netledger.web") / "static" / name).read_bytes()


@cache
def _digest(name: str) -> str:
    return hashlib.sha256(_load(name)).hexdigest()[:10]


def asset_url(name: str) -> str:
    stem, _, ext = name.rpartition(".")
    return f"/static/{stem}.{_digest(name)}.{ext}"


def lookup(filename: str) -> tuple[bytes, str, bool] | None:
    """(content, content type, immutable) for ``app.css`` or a hashed ``app.<hash>.css``."""
    parts = filename.split(".")
    if len(parts) == 3:
        name, immutable = f"{parts[0]}.{parts[2]}", True
        if name not in NAMES or parts[1] != _digest(name):
            return None
    else:
        name, immutable = filename, False
    if name not in NAMES:
        return None
    ext = "." + name.rsplit(".", 1)[1]
    return _load(name), TYPES.get(ext, "application/octet-stream"), immutable
