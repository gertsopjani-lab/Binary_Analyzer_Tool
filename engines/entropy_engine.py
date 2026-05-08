"""Entropy analysis helpers (deterministic)."""

from __future__ import annotations

import math


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    length = len(data)
    for c in freq:
        if c == 0:
            continue
        p = c / length
        ent -= p * math.log2(p)
    return float(ent)

