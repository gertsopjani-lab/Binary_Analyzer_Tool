"""Path and binary-format helpers shared by CLI and tools."""

import os
import re
from urllib.parse import unquote, urlparse


def wsl_path(path: str) -> str:
    p = path.strip().strip('"').strip("'")
    if p.startswith("/"):
        return p
    if len(p) >= 2 and p[1] == ":" and p[0].isalpha():
        return f"/mnt/{p[0].lower()}/{p[2:].replace(chr(92), '/').lstrip('/')}"
    return p


def resolve_path(path: str) -> tuple[str, bool]:
    s = path.strip().strip('"').strip("'").rstrip(".,;")
    candidates = [s, wsl_path(s), os.path.expandvars(os.path.expanduser(s))]
    if "\\\\" in s:
        candidates.append(wsl_path(s.replace("\\\\", "\\")))
    if s.startswith("\\") and not s.startswith("\\\\"):
        rest = s.replace("\\", "/").lstrip("/")
        for drive in ("c", "d", "e"):
            candidates.append(f"/mnt/{drive}/{rest}")
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate, True
    return wsl_path(s), False


def normalize_path(raw: str) -> str:
    path = (raw or "").strip().strip('"').strip("'").rstrip(".,;")
    if path.lower().startswith("file://"):
        parsed = urlparse(path)
        path = unquote(parsed.path)
        if re.match(r"^/[a-zA-Z]:/", path):
            path = path[1:]
    path = os.path.expandvars(os.path.expanduser(path))
    wsl = wsl_path(path)
    if os.path.isfile(wsl):
        return wsl
    return os.path.abspath(os.path.normpath(path))


def detect_format(path: str) -> str:
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        if magic[:2] == b"MZ":
            return "PE"
        if magic[:4] == b"\x7fELF":
            return "ELF"
    except OSError:
        pass
    return "unknown"
