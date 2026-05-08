"""YARA integration (optional dependency).

This engine compiles YARA rules and scans a binary deterministically. It never
executes the target.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any


@dataclass(frozen=True)
class YaraMatch:
    rule: str
    tags: list[str]
    meta: dict[str, Any]
    strings: list[dict[str, Any]]


class YaraEngine:
    def __init__(self, rule_paths: list[str] | None = None):
        self.rule_paths = rule_paths or []
        self._rules = None

    @staticmethod
    def available() -> bool:
        try:
            import yara  # type: ignore
        except Exception:
            return False
        return True

    def _compile(self):
        import yara  # type: ignore

        if not self.rule_paths:
            # Empty ruleset: scan returns no matches. This avoids forcing the
            # user to ship rules with the repo.
            self._rules = yara.compile(source='rule AlwaysFalse { condition: false }')
            return

        file_map = {}
        for idx, path in enumerate(self.rule_paths):
            if path and os.path.isfile(path):
                file_map[f"rule_{idx}"] = path
        if not file_map:
            self._rules = yara.compile(source='rule AlwaysFalse { condition: false }')
            return
        self._rules = yara.compile(filepaths=file_map)

    def scan(self, binary_path: str, timeout: int = 20) -> dict:
        if not self.available():
            return {"error": "python-yara not installed", "source": "yara"}
        if self._rules is None:
            self._compile()
        try:
            matches = self._rules.match(binary_path, timeout=timeout)  # type: ignore[attr-defined]
        except Exception as exc:
            return {"error": str(exc), "source": "yara"}

        out: list[dict] = []
        for m in matches or []:
            out.append(
                {
                    "rule": getattr(m, "rule", ""),
                    "tags": list(getattr(m, "tags", []) or []),
                    "meta": dict(getattr(m, "meta", {}) or {}),
                    "strings": [
                        {"offset": s[0], "identifier": s[1], "data": (s[2] if isinstance(s[2], str) else repr(s[2]))[:160]}
                        for s in (getattr(m, "strings", []) or [])[:40]
                    ],
                }
            )
        return {"source": "yara", "matches": out}

