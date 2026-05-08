"""Unified graph-driven RE analysis.

The graph is intentionally JSON-friendly:
- nodes: {"id": {"kind": "function|string|import", ...}}
- edges: [{"src": "...", "dst": "...", "kind": "..."}]
- adjacency/reverse_adjacency for cheap traversal

Edge direction follows the triage question flow:
string -> function -> function -> import
"""

from __future__ import annotations

from collections import deque
import re
from typing import Iterable


SUSPICIOUS_STRING_RE = re.compile(
    r"(?i)flag|password|passwd|secret|token|api[_-]?key|license|serial|admin|"
    r"cmd\.exe|powershell|/bin/sh|http|https|debug|inject|shell|wallet|private|"
    r"encrypt|decrypt|ransom|mutex|autorun|startup"
)

CAPABILITY_RULES = {
    "injection": {
        "apis": {"VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "NtWriteVirtualMemory", "NtProtectVirtualMemory"},
        "combo": {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"},
        "strings": ("inject", "remote thread", "shellcode"),
    },
    "anti_debug": {
        "apis": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "ptrace"},
        "combo": {"IsDebuggerPresent"},
        "strings": ("debugger", "debug", "being debugged"),
    },
    "dynamic_loading": {
        "apis": {"LoadLibraryA", "LoadLibraryW", "GetProcAddress", "LdrLoadDll", "dlopen", "dlsym"},
        "combo": {"LoadLibraryA", "GetProcAddress"},
        "strings": ("loadlibrary", "getprocaddress", ".dll"),
    },
    "networking": {
        "apis": {"InternetOpenA", "InternetOpenW", "WinHttpOpen", "WinHttpConnect", "WSAStartup", "socket", "connect", "send", "recv"},
        "combo": {"socket", "connect"},
        "strings": ("http://", "https://", "tcp://", "ws://", "user-agent"),
    },
    "persistence": {
        "apis": {"RegSetValueA", "RegSetValueW", "RegCreateKeyA", "RegCreateKeyW", "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"},
        "combo": {"RegSetValueA"},
        "strings": ("run\\", "currentversion\\run", "startup", "service", "schtasks"),
    },
    "crypto": {
        "apis": {"CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt", "CryptAcquireContextA", "CryptAcquireContextW"},
        "combo": {"CryptEncrypt"},
        "strings": ("aes", "rsa", "encrypt", "decrypt", "ransom"),
    },
    "unpacking": {
        "apis": {"VirtualProtect", "RtlDecompressBuffer", "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "mprotect", "mmap"},
        "combo": {"VirtualProtect", "GetProcAddress"},
        "strings": ("upx", "unpack", "decompress"),
    },
}

BEHAVIOR_CHAINS = [
    {
        "name": "Dynamic API resolution with memory permission changes",
        "sequence": ("LoadLibraryW", "LoadLibraryA", "GetProcAddress", "VirtualProtect"),
        "required_any": (("LoadLibraryW", "LoadLibraryA"), ("GetProcAddress",), ("VirtualProtect",)),
        "behavior": "dynamic_loading_memory_modification",
        "interpretation": "dynamic loading plus runtime memory permission changes; common in unpacking, plugin systems, and runtime patching",
        "severity": "HIGH",
    },
    {
        "name": "Classic process injection chain",
        "sequence": ("VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"),
        "required_any": (("VirtualAlloc",), ("WriteProcessMemory",), ("CreateRemoteThread",)),
        "behavior": "injection",
        "interpretation": "allocation, remote process write, and thread creation form a common process injection pattern",
        "severity": "HIGH",
    },
    {
        "name": "Dynamic API resolution",
        "sequence": ("LoadLibraryW", "LoadLibraryA", "GetProcAddress"),
        "required_any": (("LoadLibraryW", "LoadLibraryA"), ("GetProcAddress",)),
        "behavior": "dynamic_loading",
        "interpretation": "runtime DLL loading and symbol resolution; can be benign but often hides delayed behavior",
        "severity": "MEDIUM",
    },
    {
        "name": "Memory permission modification",
        "sequence": ("VirtualProtect", "mprotect", "NtProtectVirtualMemory"),
        "required_any": (("VirtualProtect", "mprotect", "NtProtectVirtualMemory"),),
        "behavior": "memory_modification",
        "interpretation": "runtime permission changes can indicate unpacking, JIT behavior, or code patching",
        "severity": "MEDIUM",
    },
    {
        "name": "Anti-debug check",
        "sequence": ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "ptrace"),
        "required_any": (("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "ptrace"),),
        "behavior": "anti_debug",
        "interpretation": "debugger or tracing detection used to alter behavior under analysis",
        "severity": "MEDIUM",
    },
]


def _node_id(kind: str, value: str) -> str:
    return f"{kind}:{value}"


def _clean_function(value: str | None) -> str | None:
    if not value:
        return None
    name = str(value).strip()
    if not name or name in {"?", "None"}:
        return None
    return name


def _short_import(value: str) -> str:
    name = str(value or "").split(".")[-1]
    if name.startswith("sym.imp."):
        name = name[8:]
    return name.strip()


def _add_node(nodes: dict, kind: str, value: str, **attrs) -> str:
    node_id = _node_id(kind, value)
    node = nodes.setdefault(node_id, {"id": node_id, "kind": kind, "value": value})
    node.update({k: v for k, v in attrs.items() if v is not None})
    return node_id


def _add_edge(edges: list, adjacency: dict, reverse: dict, src: str, dst: str, kind: str, **attrs) -> None:
    if not src or not dst:
        return
    edge = {"src": src, "dst": dst, "kind": kind}
    edge.update({k: v for k, v in attrs.items() if v is not None})
    edges.append(edge)
    adjacency.setdefault(src, [])
    reverse.setdefault(dst, [])
    if dst not in adjacency[src]:
        adjacency[src].append(dst)
    if src not in reverse[dst]:
        reverse[dst].append(src)


def _dedupe_edges(edges: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for edge in edges:
        key = (edge.get("src"), edge.get("dst"), edge.get("kind"), edge.get("address"))
        if key in seen:
            continue
        seen.add(key)
        out.append(edge)
    return out


def detect_capabilities(imports: Iterable[str], strings: Iterable[str], function_names: Iterable[str], behavior_scores: dict | None = None) -> dict:
    """Lightweight capa/YARA-like behavior clustering from local evidence."""
    import_set = {_short_import(name) for name in imports or [] if name}
    lower_strings = [str(s).lower() for s in strings or []]
    lower_functions = [str(f).lower() for f in function_names or []]
    behavior_clusters = (behavior_scores or {}).get("clusters") or {}

    clusters: dict[str, list[dict]] = {}
    total_weight = 0.0
    for capability, rule in CAPABILITY_RULES.items():
        evidence = []
        api_hits = sorted(api for api in rule["apis"] if api in import_set)
        if api_hits:
            evidence.extend({"type": "api", "value": api} for api in api_hits)
        combo = sorted(api for api in rule["combo"] if api in import_set)
        if len(combo) >= min(2, len(rule["combo"])):
            evidence.append({"type": "api_combo", "value": " + ".join(combo)})
        for pattern in rule["strings"]:
            for value in lower_strings[:500]:
                if pattern in value:
                    evidence.append({"type": "string_pattern", "value": pattern})
                    break
            for value in lower_functions[:500]:
                if pattern in value:
                    evidence.append({"type": "function_name", "value": pattern})
                    break
        if behavior_clusters.get(capability):
            evidence.append({"type": "import_cluster", "value": capability})

        if evidence:
            clusters[capability] = evidence[:30]
            total_weight += min(1.0, 0.2 + 0.16 * len(evidence))

    confidence = min(1.0, total_weight / max(1, min(4, len(clusters) or 1)))
    return {"clusters": clusters, "confidence": round(confidence, 2)}


def build_analysis_graph(scan: dict) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    adjacency: dict[str, list[str]] = {}
    reverse: dict[str, list[str]] = {}

    functions = scan.get("functions") or (scan.get("radare2") or {}).get("functions") or []
    for func in functions:
        if not isinstance(func, dict):
            continue
        name = _clean_function(func.get("name"))
        if not name:
            continue
        _add_node(nodes, "function", name, address=func.get("offset") or func.get("address"), size=func.get("size"))

    callgraph = scan.get("callgraph") or {}
    for edge in callgraph.get("edges") or []:
        src_name = _clean_function(edge.get("from"))
        dst_name = _clean_function(edge.get("to"))
        if not src_name or not dst_name:
            continue
        src = _add_node(nodes, "function", src_name)
        dst = _add_node(nodes, "function", dst_name)
        _add_edge(edges, adjacency, reverse, src, dst, "calls")

    xrefs = scan.get("xrefs") or {}
    for item in xrefs.get("strings") or []:
        value = str(item.get("string") or "")
        if not value:
            continue
        s_node = _add_node(nodes, "string", value, address=item.get("string_address"), suspicious=bool(SUSPICIOUS_STRING_RE.search(value)))
        for ref in item.get("xrefs_to_string") or []:
            fn_name = _clean_function(ref.get("function"))
            if not fn_name:
                continue
            f_node = _add_node(nodes, "function", fn_name)
            _add_edge(edges, adjacency, reverse, s_node, f_node, "xref_string", address=ref.get("from"), ref_type=ref.get("type"))

    for item in xrefs.get("imports") or []:
        name = _short_import(item.get("import") or "")
        if not name:
            continue
        i_node = _add_node(nodes, "import", name, address=item.get("address"))
        for ref in item.get("xrefs_to_import") or []:
            fn_name = _clean_function(ref.get("function"))
            if not fn_name:
                continue
            f_node = _add_node(nodes, "function", fn_name)
            _add_edge(edges, adjacency, reverse, f_node, i_node, "uses_import", address=ref.get("from"), ref_type=ref.get("type"))

    # If import xrefs were unavailable, still connect obvious sym.imp callgraph edges.
    for edge in callgraph.get("edges") or []:
        dst_name = str(edge.get("to") or "")
        if "sym.imp." not in dst_name:
            continue
        src_name = _clean_function(edge.get("from"))
        imp = _short_import(dst_name)
        if not src_name or not imp:
            continue
        f_node = _add_node(nodes, "function", src_name)
        i_node = _add_node(nodes, "import", imp)
        _add_edge(edges, adjacency, reverse, f_node, i_node, "uses_import")

    edges = _dedupe_edges(edges)
    adjacency = {}
    reverse = {}
    for edge in edges:
        adjacency.setdefault(edge["src"], [])
        reverse.setdefault(edge["dst"], [])
        if edge["dst"] not in adjacency[edge["src"]]:
            adjacency[edge["src"]].append(edge["dst"])
        if edge["src"] not in reverse[edge["dst"]]:
            reverse[edge["dst"]].append(edge["src"])

    entry_candidates = _entry_candidates(nodes, scan)
    string_provenance = _string_provenance(nodes, reverse, entry_candidates)
    return {
        "nodes": nodes,
        "edges": edges,
        "adjacency": adjacency,
        "reverse_adjacency": reverse,
        "entry_candidates": entry_candidates,
        "string_provenance": string_provenance,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "functions": sum(1 for n in nodes.values() if n.get("kind") == "function"),
            "strings": sum(1 for n in nodes.values() if n.get("kind") == "string"),
            "imports": sum(1 for n in nodes.values() if n.get("kind") == "import"),
        },
    }


def _entry_candidates(nodes: dict, scan: dict) -> list[str]:
    preferred = ("main", "sym.main", "entry0", "start", "sym._start")
    by_value = {node["value"]: node_id for node_id, node in nodes.items() if node.get("kind") == "function"}
    out = [by_value[name] for name in preferred if name in by_value]
    entry = ((scan.get("architecture") or {}).get("entry_point") or (scan.get("radare2") or {}).get("info", {}).get("entry"))
    if entry:
        for node_id, node in nodes.items():
            if node.get("kind") == "function" and node.get("address") == entry and node_id not in out:
                out.append(node_id)
    return out[:5]


def _shortest_path(adjacency: dict, starts: list[str], target: str, max_depth: int = 8) -> list[str]:
    if not starts or not target:
        return []
    queue = deque((start, [start]) for start in starts if start)
    seen = set(starts)
    while queue:
        node, path = queue.popleft()
        if node == target:
            return path
        if len(path) > max_depth:
            continue
        for nxt in adjacency.get(node, [])[:200]:
            if nxt in seen:
                continue
            seen.add(nxt)
            queue.append((nxt, path + [nxt]))
    return []


def _string_provenance(nodes: dict, reverse: dict, entry_candidates: list[str]) -> dict:
    provenance = {}
    call_adjacency = {}
    for dst, srcs in reverse.items():
        if nodes.get(dst, {}).get("kind") == "function":
            for src in srcs:
                if nodes.get(src, {}).get("kind") == "function":
                    call_adjacency.setdefault(src, []).append(dst)

    for node_id, node in nodes.items():
        if node.get("kind") != "string":
            continue
        refs = [src for src in reverse.get(node_id, []) if nodes.get(src, {}).get("kind") == "function"]
        # Graph direction is string -> function; reverse map will not have the
        # function refs, so read adjacency for this edge kind too.
        refs.extend(dst for dst in [] if dst)
        refs = [edge_dst for edge_src, edge_dsts in [] for edge_dst in edge_dsts] if False else refs
        provenance[node["value"]] = {
            "address": node.get("address"),
            "referencing_functions": [],
            "call_paths": [],
        }
    return provenance


def attach_string_provenance(graph: dict) -> dict:
    nodes = graph.get("nodes") or {}
    entry_candidates = graph.get("entry_candidates") or []
    call_adjacency = {}
    string_refs: dict[str, list[str]] = {}
    for edge in graph.get("edges") or []:
        if edge.get("kind") == "calls":
            call_adjacency.setdefault(edge["src"], []).append(edge["dst"])
        elif edge.get("kind") == "xref_string":
            string_refs.setdefault(edge["src"], []).append(edge["dst"])

    provenance = {}
    for string_node, refs in string_refs.items():
        node = nodes.get(string_node) or {}
        call_paths = []
        for ref in refs[:20]:
            path = _shortest_path(call_adjacency, entry_candidates, ref)
            if path:
                call_paths.append([nodes.get(n, {}).get("value", n) for n in path])
        provenance[node.get("value", string_node)] = {
            "address": node.get("address"),
            "referencing_functions": [nodes.get(ref, {}).get("value", ref) for ref in refs[:50]],
            "call_paths": call_paths[:10],
        }
    graph["string_provenance"] = provenance
    return graph


def score_functions(graph: dict, behavior_scores: dict | None = None, capabilities: dict | None = None) -> dict:
    nodes = graph.get("nodes") or {}
    edges = graph.get("edges") or []
    adjacency = graph.get("adjacency") or {}
    reverse = graph.get("reverse_adjacency") or {}
    import_weights = (behavior_scores or {}).get("hits") or {}
    capability_clusters = (capabilities or {}).get("clusters") or {}

    scores = {}
    for node_id, node in nodes.items():
        if node.get("kind") != "function":
            continue
        score = 0.0
        reasons = []
        outgoing = adjacency.get(node_id, [])
        incoming = reverse.get(node_id, [])
        centrality = min(5.0, (len(outgoing) + len(incoming)) * 0.35)
        if centrality:
            score += centrality
            reasons.append(f"centrality={centrality:.1f}")
        for edge in edges:
            if edge.get("src") == node_id and edge.get("kind") == "uses_import":
                imp = nodes.get(edge.get("dst"), {}).get("value")
                weight = float(import_weights.get(imp, 0))
                if weight:
                    score += weight
                    reasons.append(f"uses {imp} (+{weight:g})")
            if edge.get("dst") == node_id and edge.get("kind") == "xref_string":
                string_value = nodes.get(edge.get("src"), {}).get("value", "")
                if SUSPICIOUS_STRING_RE.search(string_value):
                    score += 3.0
                    reasons.append(f"refs suspicious string {string_value[:48]}")
        lower_name = str(node.get("value", "")).lower()
        for cap, evidence in capability_clusters.items():
            if cap in lower_name:
                score += 2.0
                reasons.append(f"name matches {cap}")
            for ev in evidence[:20]:
                value = str(ev.get("value", "")).lower() if isinstance(ev, dict) else str(ev).lower()
                if value and value in lower_name:
                    score += 1.0
                    reasons.append(f"capability context {cap}")
                    break
        scores[node["value"]] = {"score": round(score, 2), "reasons": reasons[:12]}
    ranked = sorted(scores.items(), key=lambda item: (-item[1]["score"], item[0]))
    return {"scores": scores, "top": [{"function": name, **data} for name, data in ranked[:20] if data["score"] > 0]}


def _function_imports(graph: dict) -> dict[str, set[str]]:
    nodes = graph.get("nodes") or {}
    out: dict[str, set[str]] = {}
    for edge in graph.get("edges") or []:
        if edge.get("kind") != "uses_import":
            continue
        fn = nodes.get(edge.get("src"), {}).get("value")
        api = nodes.get(edge.get("dst"), {}).get("value")
        if fn and api:
            out.setdefault(fn, set()).add(_short_import(api))
    return out


def detect_behavior_chains(graph: dict, function_scores: dict | None = None) -> list[dict]:
    """Detect behavior-level API chains per function, suppressing API spam."""
    scores = (function_scores or {}).get("scores") or {}
    imports_by_function = _function_imports(graph)
    chains = []
    for function, imports in imports_by_function.items():
        for rule in BEHAVIOR_CHAINS:
            matched_sequence = []
            ok = True
            for group in rule["required_any"]:
                hit = next((api for api in group if api in imports), None)
                if not hit:
                    ok = False
                    break
                matched_sequence.append(hit)
            if not ok:
                continue
            score = float((scores.get(function) or {}).get("score") or 0.0)
            confidence = min(0.99, 0.52 + 0.1 * len(matched_sequence) + min(0.22, score / 80.0))
            chains.append(
                {
                    "name": rule["name"],
                    "behavior": rule["behavior"],
                    "function": function,
                    "sequence": matched_sequence,
                    "interpretation": rule["interpretation"],
                    "confidence": round(confidence, 2),
                    "severity": rule["severity"],
                    "function_score": score,
                }
            )
    seen = set()
    out = []
    for chain in sorted(chains, key=lambda item: (-item["confidence"], -item["function_score"], item["function"])):
        key = (chain["function"], chain["behavior"])
        if key in seen:
            continue
        seen.add(key)
        out.append(chain)
    return out


def rank_suspicious_paths(graph: dict, function_scores: dict, behavior_chains: list[dict] | None = None, max_paths: int = 20) -> list[dict]:
    nodes = graph.get("nodes") or {}
    adjacency = graph.get("adjacency") or {}
    entry = graph.get("entry_candidates") or []
    scores = function_scores.get("scores") or {}
    targets = [
        _node_id("function", item["function"])
        for item in function_scores.get("top", [])[:40]
        if item.get("score", 0) >= 3
    ]
    paths = []
    chain_by_function = {item.get("function"): item for item in behavior_chains or []}
    for target in targets:
        path = _shortest_path(adjacency, entry, target, max_depth=8)
        if not path:
            path = [target]
        target_name = nodes.get(target, {}).get("value")
        terminal_imports = [n for n in adjacency.get(target, []) if nodes.get(n, {}).get("kind") == "import"]
        chain = chain_by_function.get(target_name)
        if chain:
            names = [nodes.get(node, {}).get("value", node) for node in path]
            score = (scores.get(target_name, {}) or {}).get("score", 0) + chain.get("confidence", 0) * 10
            paths.append(
                {
                    "path": names + chain.get("sequence", []),
                    "score": round(score, 2),
                    "sink": chain.get("sequence", [])[-1] if chain.get("sequence") else target_name,
                    "behavior": chain.get("behavior"),
                }
            )
        for imp in terminal_imports[:3]:
            full_path = path + [imp]
            names = [nodes.get(node, {}).get("value", node) for node in full_path]
            score = sum((scores.get(nodes.get(node, {}).get("value", ""), {}) or {}).get("score", 0) for node in full_path)
            score += 2.0 if terminal_imports else 0.0
            paths.append({"path": names, "score": round(score, 2), "sink": nodes.get(imp, {}).get("value")})
        if not terminal_imports:
            names = [nodes.get(node, {}).get("value", node) for node in path]
            score = (scores.get(nodes.get(target, {}).get("value", ""), {}) or {}).get("score", 0)
            paths.append({"path": names, "score": round(score, 2), "sink": names[-1] if names else None})
    deduped = []
    seen = set()
    for item in sorted(paths, key=lambda row: (-row["score"], " -> ".join(row["path"]))):
        key = tuple(item["path"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
        if len(deduped) >= max_paths:
            break
    return deduped
