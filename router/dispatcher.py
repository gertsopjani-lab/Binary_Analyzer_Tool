"""Dispatcher skeleton.

In this iteration we keep the existing agent.py routing, but provide a place to
move deterministic routing and caching decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ctf_agent.session.cache_manager import CacheManager
from ctf_agent.session.state_manager import StateManager


@dataclass
class DispatchContext:
    state: StateManager
    cache: CacheManager
    session: Any  # Agents SDK SQLiteSession (kept dynamic)

