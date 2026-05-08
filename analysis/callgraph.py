"""Call graph extraction and queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class CallGraphStats:
    nodes: int
    edges: int
    hot_functions: list[tuple[str, int]]


def build_callgraph(edges: Iterable[tuple[str, str]]):
    """Build a networkx DiGraph from edges.

    This function is optional-dependency safe: it returns (None, error) if
    networkx isn't installed.
    """
    try:
        import networkx as nx  # type: ignore
    except Exception as exc:  # pragma: no cover
        return None, f"networkx unavailable: {exc}"

    g = nx.DiGraph()
    g.add_edges_from((str(a), str(b)) for a, b in edges if a and b)
    return g, None


def stats(graph) -> CallGraphStats:
    try:
        degrees = sorted(((n, int(graph.out_degree(n))) for n in graph.nodes), key=lambda x: (-x[1], x[0]))
    except Exception:
        degrees = []
    return CallGraphStats(nodes=int(graph.number_of_nodes()), edges=int(graph.number_of_edges()), hot_functions=degrees[:15])


def callers_of(graph, target: str, limit: int = 50) -> list[str]:
    if not graph or not target:
        return []
    if target not in graph:
        return []
    return list(list(graph.predecessors(target))[:limit])


def callees_of(graph, source: str, limit: int = 50) -> list[str]:
    if not graph or not source:
        return []
    if source not in graph:
        return []
    return list(list(graph.successors(source))[:limit])


def trace_path(graph, source: str, target: str, max_hops: int = 8) -> list[str]:
    """Find a short path from source to target, bounded by max_hops."""
    if not graph or not source or not target:
        return []
    try:
        import networkx as nx  # type: ignore
    except Exception:  # pragma: no cover
        return []
    if source not in graph or target not in graph:
        return []
    try:
        path = nx.shortest_path(graph, source=source, target=target)
    except Exception:
        return []
    return path[: max_hops + 1]

