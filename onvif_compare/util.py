"""Shared utility functions.

Kept deliberately small.  No business logic lives here.
"""

from __future__ import annotations

import hashlib
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def sha256_file(path: Path) -> str:
    """Return the lowercase hex SHA-256 digest of *path*."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(tz=timezone.utc)


def format_utc(dt: datetime) -> str:
    """Format *dt* as ``YYYY-MM-DDTHH:MM:SS.ffffffZ``."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def local_ip_for(host: str, port: int) -> str:
    """Return the local IP address that would be used to reach *host*:*port*."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((host, port))
        return sock.getsockname()[0]


def slugify_stream(tcp_stream: int) -> str:
    """Return a zero-padded stream label, e.g. ``stream_012``."""
    return f"stream_{tcp_stream:03d}"
