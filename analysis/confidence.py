"""Evidence-backed confidence scoring.

Confidence must be deterministic and based on available evidence:
- multiple independent indicators
- xref presence
- decompiler evidence (when available)
- engine agreement (radare2 + pefile + strings + capa + yara)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConfidenceResult:
    confidence: float
    reasons: list[str]


def _clamp01(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


def confidence_for_finding(flag: str, evidence: list[str] | None, signals: dict | None = None) -> ConfidenceResult:
    evidence = evidence or []
    signals = signals or {}
    reasons: list[str] = []
    score = 0.35  # baseline: heuristic-only

    # Evidence count
    if len(evidence) >= 1:
        score += 0.12
        reasons.append("has evidence items")
    if len(evidence) >= 3:
        score += 0.10
        reasons.append("multiple evidence items")

    # Engine agreement
    engines = signals.get("engines") or []
    if isinstance(engines, list) and len(set(engines)) >= 2:
        score += 0.15
        reasons.append("multiple engines agree")

    # Xref / callgraph confirmation
    if signals.get("xrefs_confirmed"):
        score += 0.18
        reasons.append("xrefs confirm usage")
    if signals.get("call_path_confirmed"):
        score += 0.10
        reasons.append("call path exists")

    # Capability confirmation
    if signals.get("capa_capability"):
        score += 0.15
        reasons.append("capa capability match")
    if signals.get("yara_match"):
        score += 0.10
        reasons.append("yara match")

    # Flag-specific bumpers
    lower = (flag or "").lower()
    if "hardcoded" in lower and signals.get("string_literal"):
        score += 0.15
        reasons.append("literal string evidence")
    if "dangerous" in lower and signals.get("import_hit"):
        score += 0.12
        reasons.append("import evidence")

    return ConfidenceResult(confidence=_clamp01(score), reasons=reasons or ["heuristic confidence"])

