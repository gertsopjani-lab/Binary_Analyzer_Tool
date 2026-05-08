"""Cross-reference traversal built on deterministic evidence."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class XrefNode:
    kind: str  # "string" | "import" | "function"
    value: str


def build_string_provenance_tree(string_value: str, string_vaddr: str, xrefs: list[dict], call_path: list[str] | None = None) -> dict:
    """Return a compact provenance object suitable for terminal rendering."""
    callers = []
    for ref in xrefs or []:
        callers.append(
            {
                "from": ref.get("from"),
                "function": ref.get("function") or "?",
                "type": ref.get("type"),
            }
        )
    return {
        "string": string_value,
        "string_address": string_vaddr,
        "xrefs_to_string": callers[:50],
        "call_path": call_path or [],
    }

