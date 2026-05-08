"""Command parsing and query normalization.

This mirrors the existing in agent.py but isolates it so the UI and dispatcher
can evolve without turning agent.py into a monolith.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from tools.paths import resolve_path, wsl_path


@dataclass(frozen=True)
class Command:
    type: str
    payload: dict


def split_command(text: str) -> list[str]:
    try:
        return [part.strip('"').strip("'") for part in shlex.split(text, posix=False)]
    except ValueError:
        return text.split()


def direct_scan_path(text: str) -> str | None:
    stripped = text.strip()
    unquoted = stripped.strip('"').strip("'")
    if re.match(r"^[a-zA-Z]:[/\\]", unquoted) or unquoted.startswith(("/", "./", "../")):
        resolved, found = resolve_path(unquoted)
        return resolved if found else None
    for kw in ("load ", "scan ", "analyze "):
        if stripped.lower().startswith(kw):
            raw = stripped[len(kw):].strip().strip('"').strip("'")
            resolved, found = resolve_path(raw)
            return resolved if found else raw
    return None


def parse(user_input: str) -> Command:
    text = user_input.strip()
    lower = text.lower().strip()
    if lower in {"help", "h", "?"}:
        return Command("help", {})
    if lower in {"clear session", "clear", "reset"}:
        return Command("clear", {})
    if lower in {"active target", "target", "active", "history"}:
        return Command("active", {})
    path = direct_scan_path(text)
    if path:
        return Command("scan", {"path": path})
    if lower.startswith("decompile "):
        func = text.split(None, 1)[1].strip()
        return Command("decompile", {"function": func or "main"})
    return Command("message", {"text": text})

