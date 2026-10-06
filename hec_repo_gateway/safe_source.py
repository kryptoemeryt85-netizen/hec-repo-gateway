"""Restricted API. Source mounts are read-only; snapshots stay in /data."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOTS = ("/homeassistant", "/addon_configs/a0d7b954_appdaemon/apps")
DATA = Path("/data")
LOCK = threading.Lock()
MAX_BYTES = 1024 * 1024
GOODWE_WRITE = 0


def audit(event, **fields):
    DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (DATA / "audit.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"time": time.time(), "event": event, **fields}) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def read_allowed(raw):
    if not isinstance(raw, str) or len(raw) > 1024:
        raise ValueError("Invalid path")
    path = Path(raw)
    if not path.is_absolute() or any(x in (".", "..") for x in raw.split("/")):
        raise ValueError("Invalid path")
    root = next((r for r in ROOTS if raw.startswith(r + "/")), None)
    if root is None:
        raise ValueError("Path outside allowlist")
    parts = path.relative_to(root).parts
    if any(x.startswith(".") or re.search(r"goodwe|build\d+|tariff|taryf|secret|credential|token|password|id_rsa|id_ed25519", x, re.I) for x in parts):
        raise ValueError("Protected path")
    if path.suffix.lower() not in (".py", ".yaml", ".yml", ".json", ".md", ".txt"):
        raise ValueError("Unsupported file type")
    # Open every component without following symlinks, including the mount root.
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file_fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("Only regular single-link files allowed")
            content = stream.read(MAX_BYTES + 1)
        if len(content) > MAX_BYTES:
            raise ValueError("File too large")
        content.decode("utf-8")
        return content
    finally:
        os.close(fd)

