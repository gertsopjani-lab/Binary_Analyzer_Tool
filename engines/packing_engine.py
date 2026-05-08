"""Packed-binary heuristics for PE/ELF (deterministic).

This module produces:
- packed: bool
- confidence: 0..1
- evidence: list[str]
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .entropy_engine import shannon_entropy


UPX_SECTION_NAMES = {".upx0", ".upx1", "upx0", "upx1"}
SUSPICIOUS_SECTION_NAMES = {".aspack", ".boom", ".petite", ".themida", ".vmp0", ".vmp1", ".packed", ".mpress"}


@dataclass(frozen=True)
class PackingResult:
    packed: bool
    confidence: float
    evidence: list[str]


def _clamp01(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


def detect_pe_packing(pe_scan: dict, binary_path: str) -> PackingResult:
    evidence: list[str] = []
    score = 0.0

    sections = pe_scan.get("sections") or []
    if sections:
        high_entropy = [s for s in sections if float(s.get("entropy") or 0) >= 7.2]
        if high_entropy:
            score += 0.45
            evidence.append(f"high_entropy_sections={len(high_entropy)} (>=7.2)")

        names = {str(s.get("name") or "").strip().lower() for s in sections}
        if names & UPX_SECTION_NAMES:
            score += 0.6
            evidence.append("UPX section names present")
        if names & {n.lower() for n in SUSPICIOUS_SECTION_NAMES}:
            score += 0.4
            evidence.append("packer-like section names present")

        rwx = [s for s in sections if s.get("executable") and s.get("writable")]
        if rwx:
            score += 0.35
            evidence.append(f"rwx_sections={len(rwx)}")

    imports = ((pe_scan.get("symbols") or {}).get("imports")) or []
    if isinstance(imports, list) and len(imports) <= 5:
        score += 0.2
        evidence.append(f"tiny_import_table={len(imports)}")

    # signature sniffing
    try:
        with open(binary_path, "rb") as f:
            data = f.read(4096 * 32)
        if re.search(rb"UPX!", data):
            score += 0.6
            evidence.append("UPX signature bytes found")
    except Exception:
        pass

    packed = score >= 0.65
    return PackingResult(packed=packed, confidence=_clamp01(score), evidence=evidence or ["no strong packing indicators"])


def detect_generic_packing(binary_path: str, window: int = 65536) -> PackingResult:
    evidence: list[str] = []
    score = 0.0
    try:
        size = os.path.getsize(binary_path)
        with open(binary_path, "rb") as f:
            data = f.read(min(size, window))
        ent = shannon_entropy(data)
        if ent >= 7.2:
            score += 0.55
            evidence.append(f"high_file_entropy={ent:.2f}")
        else:
            evidence.append(f"file_entropy={ent:.2f}")
    except Exception as exc:
        return PackingResult(packed=False, confidence=0.0, evidence=[f"entropy_failed: {exc}"])

    packed = score >= 0.65
    return PackingResult(packed=packed, confidence=_clamp01(score), evidence=evidence)

