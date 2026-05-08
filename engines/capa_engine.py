"""FLARE CAPA integration (optional).

CAPA is typically used via the `capa` CLI. This engine wraps the CLI in a
deterministic way and caches the summarized capability set. If the CLI is not
available, this engine returns an informative error and does nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess


@dataclass(frozen=True)
class CapaConfig:
    timeout_s: int = 60
    max_rules: int = 2000


class CapaEngine:
    def __init__(self, config: CapaConfig | None = None, rules_dir: str | None = None):
        self.config = config or CapaConfig()
        self.rules_dir = rules_dir

    @staticmethod
    def available() -> bool:
        return bool(shutil.which("capa"))

    def scan(self, binary_path: str) -> dict:
        if not self.available():
            return {"error": "capa CLI not found on PATH", "source": "capa"}

        cmd = ["capa", "-q", "-j"]
        if self.rules_dir:
            cmd.extend(["-r", self.rules_dir])
        cmd.append(binary_path)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.timeout_s)
        except subprocess.TimeoutExpired:
            return {"error": f"capa timed out after {self.config.timeout_s}s", "source": "capa"}
        except Exception as exc:
            return {"error": str(exc), "source": "capa"}

        if result.returncode != 0:
            return {"error": (result.stderr or result.stdout or "").strip()[:2000], "source": "capa"}

        try:
            payload = json.loads(result.stdout) if result.stdout else {}
        except Exception as exc:
            return {"error": f"capa JSON parse failed: {exc}", "source": "capa"}

        # Compact capability set.
        matches = payload.get("rules") or {}
        caps = []
        if isinstance(matches, dict):
            for rule_name, meta in matches.items():
                caps.append(
                    {
                        "rule": rule_name,
                        "namespace": (meta.get("meta") or {}).get("namespace") if isinstance(meta, dict) else None,
                        "scope": (meta.get("meta") or {}).get("scope") if isinstance(meta, dict) else None,
                        "description": (meta.get("meta") or {}).get("description") if isinstance(meta, dict) else None,
                    }
                )
        caps = caps[:1500]

        return {
            "source": "capa",
            "meta": payload.get("meta") or {},
            "capabilities": caps,
        }

