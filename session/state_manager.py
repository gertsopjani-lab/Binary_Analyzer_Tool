"""State management for ACTIVE_SCAN and scan history.

The CLI keeps a conversational workflow, but analysis evidence should be stored
in a structured state object that other components can reuse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from typing import Any


def default_active_scan() -> dict[str, Any]:
    return {
        "path": None,
        "metadata": {},
        "imports": {},
        "exports": {},
        "strings": {},
        "xrefs": {},
        "callgraph": {},
        "capabilities": {},
        "findings": [],
        "deduplicated_findings": [],
        "confidence_scores": {},
        "function_clusters": {},
        "embeddings": {},
        "yara_matches": {},
        "decompilation": {},
        "sections": [],
        "entropy": [],
        "packed": {},
        "engine_evidence": {},  # raw cached outputs keyed by engine
        "last_topic": None,
        "last_finding": None,
        "agent_outputs": {},
    }


@dataclass
class StateManager:
    active: dict[str, Any] = field(default_factory=default_active_scan)
    history: list[str] = field(default_factory=list)

    def reset(self) -> None:
        self.active = default_active_scan()
        self.history.clear()

    def set_target(self, path: str) -> None:
        self.active["path"] = path
        if not self.history or self.history[-1] != path:
            self.history.append(path)

    def name(self) -> str:
        path = self.active.get("path")
        return os.path.basename(path) if path else "no-target"

    def set_topic(self, topic: str) -> None:
        self.active["last_topic"] = topic

    def cache_agent_output(self, key: str, value: str) -> None:
        outputs = self.active.get("agent_outputs")
        if not isinstance(outputs, dict):
            outputs = {}
            self.active["agent_outputs"] = outputs
        outputs[key] = str(value)

