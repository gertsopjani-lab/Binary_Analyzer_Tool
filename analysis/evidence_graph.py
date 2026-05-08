"""Evidence graph and deduplication.

This module groups related evidence into clusters and merges duplicate findings.
It is intentionally simple and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib


def _stable_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", "ignore")).hexdigest()[:12]


@dataclass
class EvidenceItem:
    kind: str  # "import" | "string" | "function" | "section" | "rule"
    value: str
    meta: dict

    def key(self) -> str:
        return f"{self.kind}:{self.value}"


@dataclass
class Finding:
    finding: str
    severity: str
    confidence: float
    evidence: list[EvidenceItem]
    source: str

    def signature(self) -> str:
        base = self.finding.lower().strip()
        sev = (self.severity or "").upper()
        # Deduplicate by semantic category, not by exact evidence set.
        # Evidence differences are merged into the canonical finding.
        return _stable_hash(f"{sev}:{base}")


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same signature, combining evidence and max confidence."""
    by_sig: dict[str, Finding] = {}
    for f in findings or []:
        sig = f.signature()
        existing = by_sig.get(sig)
        if not existing:
            by_sig[sig] = f
            continue
        # merge
        existing.confidence = max(existing.confidence, f.confidence)
        existing.source = ", ".join(sorted(set([existing.source, f.source])))
        existing_e = {e.key(): e for e in existing.evidence or []}
        for e in f.evidence or []:
            existing_e.setdefault(e.key(), e)
        existing.evidence = list(existing_e.values())[:60]
    return list(by_sig.values())

