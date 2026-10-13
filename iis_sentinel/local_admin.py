"""Break-glass local administrator credential, stored as a salted PBKDF2 hash in the data directory.

`SENTINEL_LOCAL_ADMIN_PASSWORD` (plain text, for development) takes precedence; installed copies use the hash file
written by `sentinelctl.py set-admin-password`, so the password never sits on disk, in the registry or in a service
definition in clear text.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any

from database import DATA_DIR

CRED_FILE = DATA_DIR / "local_admin.json"
ITERATIONS = 310_000
DEFAULT_USER = "sentinel-admin"


def hash_password(password: str, iterations: int = ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = encoded.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), base64.b64decode(salt_b64), int(iters))
        return hmac.compare_digest(dk, base64.b64decode(hash_b64))
    except (ValueError, TypeError):
        return False


def load(path: Path = CRED_FILE) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("hash"):
        return None
    return {"user": str(data.get("user") or DEFAULT_USER), "hash": str(data["hash"])}


def save(user: str, password: str, path: Path = CRED_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"user": user, "hash": hash_password(password)}), encoding="utf-8")
    os.replace(tmp, path)
