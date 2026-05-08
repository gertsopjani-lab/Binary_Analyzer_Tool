"""Deterministic cache manager.

Goal: Avoid repeatedly rescanning binaries. Cache key is derived from:
- absolute path
- file size
- last modified time
- engine name + version

Cache is stored as JSON on disk for portability.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CacheKey:
    path: str
    size: int
    mtime_ns: int
    engine: str
    version: str = "1"

    def as_filename(self) -> str:
        safe = self.path.replace("\\", "_").replace("/", "_").replace(":", "_")
        return f"{safe}__{self.size}__{self.mtime_ns}__{self.engine}__v{self.version}.json"


class CacheManager:
    def __init__(self, root_dir: str | None = None):
        root = root_dir or os.path.join(os.path.expanduser("~"), ".ctf_agent_cache")
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def key_for(self, binary_path: str, engine: str, version: str = "1") -> CacheKey:
        st = os.stat(binary_path)
        return CacheKey(path=os.path.abspath(binary_path), size=int(st.st_size), mtime_ns=int(st.st_mtime_ns), engine=engine, version=version)

    def load(self, key: CacheKey) -> dict | None:
        path = self.root / key.as_filename()
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def store(self, key: CacheKey, payload: dict) -> None:
        path = self.root / key.as_filename()
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        tmp.replace(path)

    def get_or_compute(self, binary_path: str, engine: str, compute_fn, version: str = "1") -> dict:
        key = self.key_for(binary_path, engine=engine, version=version)
        cached = self.load(key)
        if cached is not None:
            cached["_cache"] = {"hit": True, "engine": engine, "version": version}
            return cached
        payload = compute_fn()
        if isinstance(payload, dict):
            payload["_cache"] = {"hit": False, "engine": engine, "version": version}
        self.store(key, payload if isinstance(payload, dict) else {"value": payload})
        return payload

