"""Static analysis tools.

These helpers never execute the target binary. They inspect headers, imports,
symbols, strings, and decompiler/disassembler metadata.
"""

import json
import re
import shutil
import subprocess
from typing import Optional

from analysis.analysis_graph import (
    attach_string_provenance,
    build_analysis_graph,
    detect_behavior_chains,
    detect_capabilities,
    rank_suspicious_paths,
    score_functions,
)
from analysis.callgraph import build_callgraph, stats as callgraph_stats
from analysis.confidence import confidence_for_finding
from analysis.evidence_graph import EvidenceItem, Finding, merge_findings
from analysis.xrefs import build_string_provenance_tree
from engines.capa_engine import CapaEngine
from engines.import_engine import ImportEngine
from engines.packing_engine import detect_generic_packing, detect_pe_packing
from engines.radare_engine import Radare2Engine
from engines.yara_engine import YaraEngine
from session.cache_manager import CacheManager


HIGH_RISK_CALLS = {
    "gets",
    "strcpy",
    "strcat",
    "scanf",
    "sscanf",
    "fscanf",
    "sprintf",
    "vsprintf",
    "system",
    "execve",
    "execl",
    "popen",
}

REVIEW_CALLS = {
    "printf",
    "fprintf",
    "snprintf",
    "read",
    "recv",
    "memcpy",
    "memmove",
    "strncpy",
    "strncat",
}

BEHAVIORAL_IMPORTS = {
    "strcmp": "string comparison",
    "strncmp": "string comparison",
    "memcmp": "byte comparison",
    "strstr": "substring search",
    "crypt": "password hashing",
    "dlopen": "dynamic library loading",
    "dlsym": "dynamic symbol lookup",
    "ptrace": "anti-debugging or tracing",
    "fork": "process creation",
    "execve": "process execution",
    "system": "shell command execution",
    "connect": "network access",
    "socket": "network access",
    "send": "network access",
    "recv": "network access",
    "mprotect": "memory permission changes",
    "mmap": "runtime memory mapping",
}

FUNCTION_NAME_HINTS = [
    "main",
    "check",
    "valid",
    "license",
    "serial",
    "key",
    "auth",
    "login",
    "password",
    "flag",
    "secret",
    "decrypt",
    "encode",
    "decode",
    "win",
    "shell",
    "backdoor",
]

SECRET_PATTERNS = {
    "flags": [
        r"flag\{[^}\r\n]{1,200}\}",
        r"(?:picoCTF|HTB|CTF|CHTB)\{[^}\r\n]{1,200}\}",
    ],
    "passwords": [
        r"(?i)\b(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|auth)\b\s*[:=]\s*[^\s'\"<>]{4,160}",
        r"(?i)\b(?:admin|root|user|login)\b\s*[:=]\s*[^\s'\"<>]{3,120}",
    ],
    "private_keys": [
        r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----",
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
    ],
    "api_keys": [
        r"AKIA[0-9A-Z]{16}",
        r"(?i)sk-[a-z0-9_-]{20,}",
        r"(?i)(?:ghp|github_pat)_[A-Za-z0-9_]{20,}",
        r"(?i)xox[baprs]-[A-Za-z0-9-]{20,}",
        r"(?i)eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}",
    ],
    "network": [
        r"https?://[^\s'\"<>]{4,180}",
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    ],
}

BENIGN_STRING_PATTERNS = [
    r"^https?://schemas\.microsoft\.com/",
    r"^http://www\.w3\.org/",
    r"^Microsoft Windows",
    r"^VS_VERSION_INFO$",
    r"^StringFileInfo$",
    r"^VarFileInfo$",
    r"^CompanyName$",
    r"^FileDescription$",
    r"^ProductVersion$",
    r"^LegalCopyright$",
]


def _looks_benign_metadata(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return True
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in BENIGN_STRING_PATTERNS)


def _cache_get(binary_path: str, engine: str, version: str, compute_fn) -> dict:
    return CacheManager().get_or_compute(binary_path, engine, compute_fn, version=version)


def _flatten_import_names(scan: dict, radare: dict | None = None) -> list[str]:
    names = []
    symbols = scan.get("symbols") or {}
    for key in ("imports", "plt_imports", "dangerous_functions", "review_functions"):
        values = symbols.get(key) or []
        if isinstance(values, list):
            names.extend(str(v) for v in values if v)
    behavioral = symbols.get("behavioral_imports") or {}
    if isinstance(behavioral, dict):
        names.extend(str(k) for k in behavioral)
    for item in (radare or {}).get("imports") or []:
        if isinstance(item, dict) and item.get("name"):
            names.append(str(item["name"]))
    seen = set()
    out = []
    for name in names:
        short = name.split(".")[-1].strip()
        if short and short.lower() not in seen:
            seen.add(short.lower())
            out.append(short)
    return out


def _xref_function_label(ref: dict) -> str:
    return str(ref.get("function") or ref.get("from") or "?")


def build_xrefs(radare: dict, interesting_strings: list[str] | None = None) -> dict:
    """Build string/import/function xrefs in a conversational query-friendly shape."""
    interesting_strings = interesting_strings or []
    interesting_lowers = [s.lower() for s in interesting_strings if s]
    raw = radare.get("xrefs") or {}
    result = {"strings": [], "imports": [], "functions": [], "by_value": {}}

    for item in raw.get("strings") or []:
        text = str(item.get("string") or "")
        if not text:
            continue
        refs = item.get("xrefs_to_string") or []
        include = refs and (
            not interesting_lowers
            or any(needle in text.lower() or text.lower() in needle for needle in interesting_lowers[:80])
            or re.search(r"(?i)flag|password|passwd|secret|token|key|license|serial|admin|correct|wrong|http|cmd\.exe|/bin/sh", text)
        )
        if not include:
            continue
        provenance = build_string_provenance_tree(text, item.get("string_address"), refs)
        result["strings"].append(provenance)
        result["by_value"].setdefault(text, [])
        for ref in refs:
            result["by_value"][text].append(
                {
                    "function": _xref_function_label(ref),
                    "address": ref.get("from"),
                    "type": ref.get("type"),
                }
            )
        result[text] = result["by_value"][text]

    for item in raw.get("imports") or []:
        name = item.get("import")
        refs = item.get("xrefs_to_import") or []
        if not name or not refs:
            continue
        compact = {
            "import": name,
            "address": item.get("address"),
            "xrefs_to_import": refs,
            "callers": [_xref_function_label(ref) for ref in refs[:50]],
        }
        result["imports"].append(compact)
        result["by_value"][str(name)] = [
            {"function": _xref_function_label(ref), "address": ref.get("from"), "type": ref.get("type")}
            for ref in refs
        ]
        result[str(name)] = result["by_value"][str(name)]

    for item in raw.get("functions") or []:
        name = item.get("function")
        if name:
            result["functions"].append(item)

    return result


def build_callgraph_summary(radare: dict) -> dict:
    edges = radare.get("callgraph_edges") or []
    graph, error = build_callgraph(edges)
    calls_by = {}
    called_by = {}
    for src, dst in edges:
        calls_by.setdefault(src, set()).add(dst)
        called_by.setdefault(dst, set()).add(src)

    nodes = sorted(set(calls_by) | set(called_by))
    result = {
        node: {
            "calls": sorted(calls_by.get(node, set()))[:200],
            "called_by": sorted(called_by.get(node, set()))[:200],
        }
        for node in nodes[:5000]
    }
    if graph is not None:
        st = callgraph_stats(graph)
        result["stats"] = {"nodes": st.nodes, "edges": st.edges, "hot_functions": st.hot_functions}
    else:
        result["stats"] = {"nodes": len(nodes), "edges": len(edges), "error": error}
    result["edges"] = [{"from": src, "to": dst} for src, dst in edges[:5000]]
    return result


def _capability_groups(capa: dict, import_clusters: dict) -> dict:
    groups = {name: {"source": "imports", "items": values} for name, values in (import_clusters or {}).items()}
    for cap in capa.get("capabilities") or []:
        text = " ".join(str(cap.get(k) or "") for k in ("rule", "namespace", "description")).lower()
        group = None
        for name, patterns in {
            "anti_debug": ("debug", "anti-analysis"),
            "persistence": ("persist", "registry", "service", "startup"),
            "injection": ("inject", "remote thread", "process memory", "virtualalloc", "virtualprotect"),
            "crypto": ("crypto", "encrypt", "decrypt", "ransom"),
            "networking": ("network", "http", "socket", "connect", "dns"),
            "unpacking": ("unpack", "decompress", "resolve api", "loadlibrary", "getprocaddress"),
        }.items():
            if any(p in text for p in patterns):
                group = name
                break
        if group:
            groups.setdefault(group, {"source": "capa", "items": []})
            groups[group]["items"].append(cap.get("rule"))
    return groups


def _merge_capability_clusters(*cluster_sets: dict) -> dict:
    merged: dict[str, list] = {}
    for clusters in cluster_sets:
        for name, values in (clusters or {}).items():
            if isinstance(values, dict):
                values = values.get("items") or values.get("evidence") or []
            if not isinstance(values, list):
                values = [values]
            bucket = merged.setdefault(name, [])
            for value in values:
                if value not in bucket:
                    bucket.append(value)
    return merged


def _severity_from_score(score: int) -> str:
    if score >= 14:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def _finding_dict(title: str, severity: str, status: str, human: str, fix: str, evidence: list[str], source: str, signals: dict) -> dict:
    conf = confidence_for_finding(title, evidence, signals)
    return {
        "flag": title,
        "title": title,
        "status": status,
        "risk": severity,
        "severity": severity,
        "human": human,
        "fix": fix,
        "confidence": round(conf.confidence, 2),
        "confidence_reasons": conf.reasons,
        "evidence": evidence[:20],
        "source": source,
    }


def _engine_findings(scan: dict) -> list[dict]:
    findings = []

    packed = scan.get("packed") or {}
    if packed.get("is_packed") or packed.get("packed"):
        findings.append(
            _finding_dict(
                "Likely packed or obfuscated binary",
                "HIGH" if float(packed.get("confidence") or 0) >= 0.8 else "MEDIUM",
                f"confidence={float(packed.get('confidence') or 0):.2f}",
                "Packing indicators suggest code or resources may be compressed, encrypted, or unpacked at runtime.",
                "Unpack or capture the post-unpack image before trusting strings, imports, or decompiler output.",
                [str(e) for e in packed.get("evidence") or []],
                "packing_engine",
                {"engines": ["packing", "radare2"]},
            )
        )

    capa_caps = (scan.get("capabilities") or {}).get("capa", {}).get("capabilities") or []
    for cap in capa_caps[:20]:
        text = " ".join(str(cap.get(k) or "") for k in ("rule", "namespace", "description"))
        lower = text.lower()
        if not any(k in lower for k in ("debug", "persist", "inject", "crypto", "encrypt", "ransom", "network", "socket", "unpack")):
            continue
        severity = "HIGH" if any(k in lower for k in ("ransom", "inject", "persist")) else "MEDIUM"
        findings.append(
            _finding_dict(
                f"Capability: {cap.get('rule')}",
                severity,
                cap.get("namespace") or "capa",
                cap.get("description") or f"CAPA matched {cap.get('rule')}.",
                "Review the matched capability locations in CAPA/radare output and correlate with reachable functions.",
                [f"capa rule={cap.get('rule')}", f"namespace={cap.get('namespace')}"],
                "capa",
                {"engines": ["capa"], "capa_capability": True},
            )
        )

    for match in (scan.get("yara_matches") or {}).get("matches") or []:
        lower = " ".join([match.get("rule", ""), " ".join(match.get("tags") or []), json.dumps(match.get("meta") or {})]).lower()
        severity = "HIGH" if any(k in lower for k in ("ransom", "malware", "trojan", "inject")) else "MEDIUM"
        findings.append(
            _finding_dict(
                f"YARA match: {match.get('rule')}",
                severity,
                ", ".join(match.get("tags") or []) or "matched",
                "A YARA rule matched byte/string patterns in the binary.",
                "Treat this as a rule hit, then confirm behavior with imports, xrefs, and decompiler evidence.",
                [f"rule={match.get('rule')}", f"strings={len(match.get('strings') or [])}"],
                "yara",
                {"engines": ["yara"], "yara_match": True},
            )
        )
    return findings


def _graph_contextual_findings(scan: dict) -> list[dict]:
    """Create behavior-cluster findings from graph relationships."""
    graph = scan.get("analysis_graph") or {}
    nodes = graph.get("nodes") or {}
    reverse = graph.get("reverse_adjacency") or {}
    behavior = scan.get("behavior_scores") or {}
    weighted_imports = behavior.get("hits") or {}
    review_imports = set((scan.get("symbols") or {}).get("review_functions") or [])
    dangerous_imports = set((scan.get("symbols") or {}).get("dangerous_functions") or [])
    findings = []
    function_scores = (scan.get("function_scores") or {}).get("scores") or {}
    chains = scan.get("behavior_chains") or []

    chains_by_behavior: dict[str, list[dict]] = {}
    for chain in chains:
        chains_by_behavior.setdefault(chain.get("name") or "Behavior chain", []).append(chain)

    for chain_name, grouped_chains in chains_by_behavior.items():
        ranked_chains = sorted(grouped_chains, key=lambda item: (-float(item.get("function_score") or 0), -float(item.get("confidence") or 0)))[:8]
        first = ranked_chains[0]
        evidence = [
            f"{item.get('function')} score={item.get('function_score')} sequence={' -> '.join(item.get('sequence') or [])}"
            for item in ranked_chains
        ]
        findings.append(
            _finding_dict(
                chain_name,
                first.get("severity") or "MEDIUM",
                first.get("behavior") or "behavior_chain",
                f"{chain_name} detected in {len(grouped_chains)} function(s). Assessment: {first.get('interpretation')}.",
                "Use the global next steps: inspect ranked behavior chains, then decompile the top function and verify reachability/arguments.",
                evidence,
                "behavior_chain",
                {"engines": ["graph", "imports"], "import_hit": True, "call_path_confirmed": True},
            )
        )

    cluster_members: dict[str, dict[str, set[str]]] = {}

    for edge in graph.get("edges") or []:
        if edge.get("kind") != "uses_import":
            continue
        func = nodes.get(edge.get("src"), {})
        imp = nodes.get(edge.get("dst"), {})
        api = imp.get("value")
        fn = func.get("value")
        if not api or not fn:
            continue
        api_lower = str(api).lower()
        api_weight = int(weighted_imports.get(api, 0))
        is_dangerous = api in dangerous_imports or api_lower in HIGH_RISK_CALLS
        if not is_dangerous and api_weight < 4:
            continue
        if is_dangerous:
            cluster = "Unsafe input / command execution cluster"
        else:
            cluster = (behavior.get("details") or {}).get(api, {}).get("reason") or "Behavioral API cluster"
            cluster = f"{cluster.title()} cluster"
        member = cluster_members.setdefault(cluster, {})
        member.setdefault(fn, set()).add(api)

    for cluster, functions in cluster_members.items():
        ranked = sorted(
            functions.items(),
            key=lambda item: (-(function_scores.get(item[0], {}) or {}).get("score", 0), item[0]),
        )[:8]
        if not ranked:
            continue
        severity = "HIGH" if "Unsafe" in cluster or any(api.lower() in HIGH_RISK_CALLS for _, apis in ranked for api in apis) else "MEDIUM"
        evidence = [
            f"{fn} score={(function_scores.get(fn, {}) or {}).get('score', 0)} apis={', '.join(sorted(apis))}"
            for fn, apis in ranked
        ]
        findings.append(
            _finding_dict(
                cluster,
                severity,
                f"{len(functions)} function(s)",
                f"{cluster} identified across {len(functions)} function(s), ranked by graph score and API evidence.",
                "Use the global next steps to review the top-ranked functions first.",
                evidence,
                "analysis_graph",
                {"engines": ["radare2", "imports", "graph"], "import_hit": True, "xrefs_confirmed": True},
            )
        )
    return findings[:20]


def prioritize_findings(findings: list[dict], medium_limit: int = 8) -> tuple[list[dict], list[dict]]:
    highs = [item for item in findings if item.get("risk") == "HIGH"]
    meds = sorted(
        [item for item in findings if item.get("risk") == "MEDIUM"],
        key=lambda item: float(item.get("confidence") or 0),
        reverse=True,
    )
    lows = [item for item in findings if item.get("risk") == "LOW"]
    kept = highs + meds[:medium_limit] + lows
    additional = meds[medium_limit:]
    return kept, additional


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    graph_findings = []
    original_by_sig = {}
    for item in findings or []:
        evidence = []
        for ev in item.get("evidence") or [item.get("status") or item.get("flag")]:
            evidence.append(EvidenceItem("evidence", str(ev), {"source": item.get("source")}))
        node = Finding(
            finding=item.get("title") or item.get("flag") or "finding",
            severity=item.get("severity") or item.get("risk") or "LOW",
            confidence=float(item.get("confidence") or 0.35),
            evidence=evidence,
            source=item.get("source") or "static",
        )
        sig = node.signature()
        original_by_sig.setdefault(sig, item)
        graph_findings.append(node)

    merged = merge_findings(graph_findings)
    out = []
    for node in merged:
        base = dict(original_by_sig.get(node.signature()) or {})
        base["flag"] = base.get("flag") or node.finding
        base["title"] = base.get("title") or node.finding
        base["risk"] = base.get("risk") or node.severity
        base["severity"] = base.get("severity") or node.severity
        base["confidence"] = round(node.confidence, 2)
        base["source"] = node.source
        base["evidence"] = [e.value for e in node.evidence]
        out.append(base)
    return out


def run_deterministic_engines(binary_path: str, scan: dict) -> dict:
    """Populate scan with cached deterministic RE engine output."""
    scan.setdefault("engine_status", {})
    strings = scan.get("strings") or {}
    interesting_strings = []
    for values in (strings.get("interesting") or {}).values():
        if isinstance(values, list):
            interesting_strings.extend(str(v) for v in values)

    radare = _cache_get(binary_path, "radare2", "5", lambda: Radare2Engine().analyze(binary_path))
    scan["radare2"] = radare
    scan["engine_status"]["radare2"] = radare.get("_cache", {})

    if not radare.get("error"):
        if radare.get("functions"):
            scan["functions"] = radare["functions"]
        if radare.get("imports"):
            existing = (scan.get("symbols") or {}).get("imports") or []
            merged_imports = _flatten_import_names(scan, radare)
            scan.setdefault("symbols", {})["imports"] = list(dict.fromkeys(existing + merged_imports))[:1000]
        if radare.get("sections"):
            scan["sections"] = radare["sections"]
        if radare.get("info"):
            info = radare["info"]
            arch = scan.setdefault("architecture", {})
            arch["arch"] = arch.get("arch") or info.get("arch")
            arch["bits"] = arch.get("bits") or info.get("bits")
            arch["entry_point"] = arch.get("entry_point") or info.get("entry")

    scan["xrefs"] = build_xrefs(radare if isinstance(radare, dict) else {}, interesting_strings)
    scan["callgraph"] = build_callgraph_summary(radare if isinstance(radare, dict) else {})

    import_names = _flatten_import_names(scan, radare if isinstance(radare, dict) else {})
    import_score = ImportEngine().score_imports(import_names)
    scan["behavior_scores"] = {
        "score": import_score.score,
        "hits": import_score.hits,
        "clusters": import_score.clusters,
        "details": {
            name: {"score": score, "reason": _import_reason(name, import_score.clusters)}
            for name, score in import_score.hits.items()
        },
    }

    if scan.get("format") == "PE":
        packed_result = detect_pe_packing(scan, binary_path)
    else:
        packed_result = detect_generic_packing(binary_path)
    scan["packed"] = {
        "is_packed": packed_result.packed,
        "packed": packed_result.packed,
        "confidence": packed_result.confidence,
        "evidence": packed_result.evidence,
    }

    yara = _cache_get(binary_path, "yara", "1", lambda: YaraEngine().scan(binary_path))
    capa = _cache_get(binary_path, "capa", "1", lambda: CapaEngine().scan(binary_path))
    function_names = [str(item.get("name")) for item in scan.get("functions") or [] if isinstance(item, dict) and item.get("name")]
    string_values = []
    for item in (radare or {}).get("strings") or []:
        if isinstance(item, dict) and item.get("string"):
            string_values.append(str(item["string"]))
    for values in (scan.get("strings") or {}).get("interesting", {}).values():
        if isinstance(values, list):
            string_values.extend(str(v) for v in values)
    lightweight_caps = detect_capabilities(import_names, string_values, function_names, scan["behavior_scores"])
    capa_groups = _capability_groups(capa if isinstance(capa, dict) else {}, import_score.clusters)
    merged_clusters = _merge_capability_clusters(lightweight_caps.get("clusters"), capa_groups, import_score.clusters)
    scan["yara_matches"] = yara
    scan["capabilities"] = {
        "capa": capa,
        "import_score": scan["behavior_scores"],
        "groups": capa_groups,
        "clusters": merged_clusters,
        "confidence": lightweight_caps.get("confidence", 0.0),
        "lightweight": lightweight_caps,
    }
    scan["function_clusters"] = merged_clusters
    graph = build_analysis_graph(scan)
    graph = attach_string_provenance(graph)
    scan["analysis_graph"] = graph
    provenance = graph.get("string_provenance") or {}
    for item in (scan.get("xrefs") or {}).get("strings") or []:
        prov = provenance.get(item.get("string")) or {}
        item["address"] = item.get("string_address") or prov.get("address")
        item["referencing_functions"] = prov.get("referencing_functions") or [
            ref.get("function") for ref in item.get("xrefs_to_string") or [] if ref.get("function")
        ]
        item["call_paths"] = prov.get("call_paths") or []
    scan["function_scores"] = score_functions(graph, scan["behavior_scores"], scan["capabilities"])
    scan["behavior_chains"] = detect_behavior_chains(graph, scan["function_scores"])
    scan["suspicious_paths"] = rank_suspicious_paths(graph, scan["function_scores"], scan["behavior_chains"])
    scan["engine_findings"] = _graph_contextual_findings(scan) + _engine_findings(scan)
    return scan


def _import_reason(name: str, clusters: dict) -> str:
    for cluster, values in (clusters or {}).items():
        if name in values:
            return cluster.replace("_", " ")
    return "suspicious API"


def run_checksec(binary_path: str) -> dict:
    """Check ELF protections using checksec, then pwntools as fallback."""
    try:
        result = subprocess.run(
            ["checksec", f"--file={binary_path}", "--output=json"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            raw = json.loads(result.stdout)
            props = list(raw.values())[0]
            return {
                "nx": props.get("nx", "unknown"),
                "pie": props.get("pie", "unknown"),
                "canary": props.get("canary", "unknown"),
                "relro": props.get("relro", "unknown"),
                "aslr": props.get("aslr", "unknown"),
                "source": "checksec",
            }
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        pass

    try:
        from pwn import ELF, context

        context.log_level = "error"
        elf = ELF(binary_path, checksec=False)
        return {
            "nx": "enabled" if elf.nx else "disabled",
            "pie": "enabled" if elf.pie else "disabled",
            "canary": "enabled" if elf.canary else "disabled",
            "relro": "full" if elf.relro == "Full" else "partial" if elf.relro == "Partial" else "disabled",
            "aslr": "unknown",
            "bits": elf.bits,
            "arch": elf.arch,
            "source": "pwntools",
        }
    except Exception as exc:
        return {"error": str(exc), "source": "fallback"}


def extract_symbols(binary_path: str) -> dict:
    """Extract imported functions, review calls, symbols, and named RE leads."""
    try:
        from pwn import ELF, context

        context.log_level = "error"
        elf = ELF(binary_path, checksec=False)
        found_dangerous = [fn for fn in sorted(HIGH_RISK_CALLS) if fn in elf.plt or fn in elf.symbols]
        review_functions = [fn for fn in sorted(REVIEW_CALLS) if fn in elf.plt or fn in elf.symbols]
        behavioral_imports = {
            fn: BEHAVIORAL_IMPORTS[fn]
            for fn in sorted(BEHAVIORAL_IMPORTS)
            if fn in elf.plt or fn in elf.symbols
        }

        win_candidates = {}
        interesting_functions = []
        for sym, addr in elf.symbols.items():
            lower = sym.lower()
            if any(kw in lower for kw in ["win", "shell", "flag", "backdoor", "secret", "get_flag"]):
                win_candidates[sym] = hex(addr)
            if addr > 0 and not sym.startswith("_") and any(hint in lower for hint in FUNCTION_NAME_HINTS):
                interesting_functions.append({"name": sym, "address": hex(addr)})

        return {
            "dangerous_functions": found_dangerous,
            "review_functions": review_functions,
            "behavioral_imports": behavioral_imports,
            "plt_imports": list(elf.plt.keys()),
            "symbols": {k: hex(v) for k, v in elf.symbols.items() if v > 0},
            "interesting_functions": interesting_functions[:50],
            "win_functions": win_candidates,
            "has_win": bool(win_candidates),
            "binary_base": hex(elf.address),
            "bits": elf.bits,
            "arch": elf.arch,
            "entry_point": hex(elf.entry),
        }
    except Exception as exc:
        return {"error": str(exc)}


def _ascii_strings(data: bytes, min_len: int = 4) -> list[str]:
    return [m.group(0).decode("latin1", "replace") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data)]


def _utf16le_strings(data: bytes, min_len: int = 4) -> list[str]:
    raw_pattern = rb"(?:[\x20-\x7e]\x00){%d,}" % min_len
    return [m.group(0).decode("utf-16le", "replace") for m in re.finditer(raw_pattern, data)]


def _unique_limited(values: list[str], limit: int = 25) -> list[str]:
    seen = set()
    out = []
    for value in values:
        clean = value.strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        out.append(clean[:220])
        if len(out) >= limit:
            break
    return out


def find_strings(binary_path: str, pattern: Optional[str] = None) -> dict:
    """Extract printable strings with an internal fallback if binutils is missing."""
    try:
        if shutil.which("strings"):
            result = subprocess.run(
                ["strings", "-n", "4", binary_path],
                capture_output=True,
                text=True,
                timeout=15,
            )
            all_strings = result.stdout.splitlines()
        else:
            with open(binary_path, "rb") as f:
                data = f.read()
            all_strings = _unique_limited(_ascii_strings(data) + _utf16le_strings(data), 5000)

        always_interesting = [
            r"/bin/sh",
            r"/bin/bash",
            r"cmd\.exe",
            r"powershell",
            r"flag\{",
            r"FLAG\{",
            r"password",
            r"passwd",
            r"secret",
            r"license",
            r"serial",
            r"backdoor",
            r"correct",
            r"wrong",
            r"try again",
            r"congratulations",
            r"CTF",
            r"picoCTF",
            r"HTB",
            r"https?://",
        ]

        interesting = {}
        for kw in always_interesting:
            matches = [s for s in all_strings if re.search(kw, s, re.IGNORECASE)]
            if matches:
                interesting[kw] = matches[:25]

        if pattern:
            custom = [s for s in all_strings if re.search(pattern, s, re.IGNORECASE)]
            interesting[f"custom:{pattern}"] = custom[:25]

        return {
            "total_strings": len(all_strings),
            "interesting": interesting,
            "all_strings": all_strings[:200],
        }
    except Exception as exc:
        return {"error": str(exc)}


def scan_embedded_secrets(binary_path: str) -> dict:
    """Read a binary and extract likely flags, passwords, keys, and tokens."""
    try:
        with open(binary_path, "rb") as f:
            data = f.read()

        ascii_values = _ascii_strings(data)
        utf16_values = _utf16le_strings(data)
        all_values = _unique_limited(ascii_values + utf16_values, 5000)
        joined = "\n".join(all_values)

        findings = {}
        for category, patterns in SECRET_PATTERNS.items():
            matches = []
            for pattern in patterns:
                matches.extend(re.findall(pattern, joined, re.IGNORECASE))
            if matches:
                clean_matches = [
                    m if isinstance(m, str) else m[0]
                    for m in matches
                    if not _looks_benign_metadata(m if isinstance(m, str) else m[0])
                ]
                if clean_matches:
                    findings[category] = _unique_limited(clean_matches)

        keyword_hits = []
        for value in all_values:
            if _looks_benign_metadata(value):
                continue
            if re.search(r"(?i)flag|password|passwd|pwd|secret|token|key|license|serial|admin|ctf|debug", value):
                keyword_hits.append(value)

        result = {
            "file_size": len(data),
            "format": "PE" if data.startswith(b"MZ") else "ELF" if data.startswith(b"\x7fELF") else "unknown",
            "findings": findings,
            "keyword_hits": _unique_limited(keyword_hits, 40),
            "sample_strings": _unique_limited(all_values, 80),
        }

        if data.startswith(b"MZ"):
            try:
                import pefile

                pe = pefile.PE(data=data, fast_load=True)
                result["pe"] = {
                    "machine": hex(pe.FILE_HEADER.Machine),
                    "sections": [s.Name.rstrip(b"\x00").decode("latin1", "replace") for s in pe.sections[:12]],
                    "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                    "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                }
            except Exception:
                result["pe"] = {"note": "PE metadata unavailable"}

        return result
    except Exception as exc:
        return {"error": str(exc)}


def decompile_function(binary_path: str, function_name: str = "main") -> dict:
    """Decompile a function with radare2, falling back to objdump disassembly."""
    try:
        r2_cmds = f"aaa; s sym.{function_name}; pdc"
        result = subprocess.run(
            ["r2", "-q", "-c", r2_cmds, binary_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        decompiled = result.stdout.strip()

        r2_disasm = f"aaa; s sym.{function_name}; pdf"
        disasm = subprocess.run(
            ["r2", "-q", "-c", r2_disasm, binary_path],
            capture_output=True,
            text=True,
            timeout=20,
        )

        if not decompiled and not disasm.stdout:
            r2_cmds2 = f"aaa; s {function_name}; pdc"
            result2 = subprocess.run(
                ["r2", "-q", "-c", r2_cmds2, binary_path],
                capture_output=True,
                text=True,
                timeout=20,
            )
            decompiled = result2.stdout.strip()

        return {
            "function": function_name,
            "decompiled": decompiled[:4000] if decompiled else "Not found",
            "disassembly": disasm.stdout[:2000] if disasm.stdout else "Not found",
        }
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ["objdump", "-d", "-M", "intel", binary_path],
                capture_output=True,
                text=True,
                timeout=20,
            )
            lines = result.stdout.split("\n")
            in_func = False
            func_lines = []
            for line in lines:
                if f"<{function_name}>:" in line:
                    in_func = True
                if in_func:
                    func_lines.append(line)
                    if line.strip() == "" and len(func_lines) > 2:
                        break
            return {
                "function": function_name,
                "decompiled": "radare2 not available",
                "disassembly": "\n".join(func_lines[:80]),
            }
        except Exception as exc:
            return {"error": str(exc)}
    except Exception as exc:
        return {"error": str(exc)}


def _run_r2_json(binary_path: str, command: str, timeout: int = 35):
    if not shutil.which("r2"):
        return None
    try:
        result = subprocess.run(
            ["r2", "-q", "-2", "-c", "aaa", "-c", command, binary_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except Exception:
        return None


def list_functions(binary_path: str, limit: int = 200) -> dict:
    """List discovered functions without running the target binary."""
    funcs = _run_r2_json(binary_path, "aflj")
    if isinstance(funcs, list):
        cleaned = []
        for item in funcs[:limit]:
            name = item.get("name") or item.get("realname") or "?"
            offset = item.get("offset")
            cleaned.append(
                {
                    "name": name,
                    "offset": hex(offset) if isinstance(offset, int) else offset,
                    "size": item.get("size"),
                    "noreturn": item.get("noreturn", False),
                    "calltype": item.get("calltype"),
                }
            )
        return {"source": "radare2", "functions": cleaned}

    symbols = extract_symbols(binary_path)
    fallback = []
    for name, address in (symbols.get("symbols") or {}).items():
        if any(hint in name.lower() for hint in FUNCTION_NAME_HINTS):
            fallback.append({"name": name, "offset": address, "size": None, "noreturn": False})
    return {"source": "symbols", "functions": fallback[:limit]}


def _interesting_function_score(name: str) -> int:
    lower = name.lower()
    score = 0
    for hint in FUNCTION_NAME_HINTS:
        if hint in lower:
            score += 3 if hint in {"main", "check", "valid", "license", "password", "flag", "secret"} else 2
    if lower.startswith(("sym.", "main", "entry")):
        score += 1
    return score


def _collect_r2_string_xrefs(binary_path: str, strings: list[dict], limit: int = 15) -> list[dict]:
    if not shutil.which("r2"):
        return []

    xrefs = []
    for item in strings[:limit]:
        vaddr = item.get("vaddr") or item.get("paddr")
        text = item.get("string") or item.get("text") or ""
        if not isinstance(vaddr, int):
            continue
        try:
            result = subprocess.run(
                ["r2", "-q", "-2", "-c", "aaa", "-c", f"axtj @ {vaddr}", binary_path],
                capture_output=True,
                text=True,
                timeout=20,
            )
            refs = json.loads(result.stdout) if result.stdout.strip() else []
        except Exception:
            refs = []
        for ref in refs[:5]:
            ref_from = ref.get("from")
            xrefs.append(
                {
                    "string": text[:120],
                    "string_address": hex(vaddr),
                    "from": hex(ref_from) if isinstance(ref_from, int) else ref_from,
                    "function": ref.get("fcn_name") or ref.get("fname"),
                    "type": ref.get("type"),
                }
            )
    return xrefs[:50]


def analyze_reverse_engineering(binary_path: str, existing_scan: Optional[dict] = None) -> dict:
    """Produce concrete starting points for manual reverse engineering."""
    existing_scan = existing_scan or {}
    symbols = existing_scan.get("symbols") or extract_symbols(binary_path)
    string_info = find_strings(binary_path)

    radare = existing_scan.get("radare2") or {}
    if isinstance(radare, dict) and radare.get("functions"):
        function_info = {"source": "radare2-cache", "functions": radare.get("functions") or []}
    else:
        function_info = list_functions(binary_path)
    functions = function_info.get("functions", [])
    priority_functions = []
    for func in functions:
        score = _interesting_function_score(func.get("name", ""))
        if score:
            item = dict(func)
            item["score"] = score
            priority_functions.append(item)
    priority_functions.sort(key=lambda item: (-item["score"], item.get("name", "")))

    r2_strings = radare.get("strings") if isinstance(radare, dict) else None
    if not r2_strings:
        r2_strings = _run_r2_json(binary_path, "izzj")
    suspicious_strings = []
    if isinstance(r2_strings, list):
        for item in r2_strings:
            text = item.get("string", "")
            if re.search(
                r"(?i)flag|password|passwd|secret|token|key|license|serial|admin|correct|wrong|http|cmd\.exe|/bin/sh",
                text,
            ):
                suspicious_strings.append(item)
    else:
        for label, values in (string_info.get("interesting") or {}).items():
            for value in values[:8]:
                suspicious_strings.append({"string": value, "reason": label})

    xrefs = []
    by_value = (existing_scan.get("xrefs") or {}).get("by_value") or {}
    if by_value:
        for item in suspicious_strings[:50]:
            text = str(item.get("string") or "")
            for ref in by_value.get(text, [])[:8]:
                xrefs.append(
                    {
                        "string": text[:120],
                        "string_address": item.get("vaddr") or item.get("address"),
                        "from": ref.get("address"),
                        "function": ref.get("function"),
                        "type": ref.get("type"),
                    }
                )
    if not xrefs:
        xrefs = _collect_r2_string_xrefs(binary_path, suspicious_strings)
    behavioral_imports = symbols.get("behavioral_imports") or {}

    notes = []
    if not shutil.which("r2"):
        notes.append("radare2 not found; function and xref coverage is limited to symbol/string metadata.")
    if not priority_functions:
        notes.append("No obviously named validation or secret-handling functions were found.")

    return {
        "function_source": function_info.get("source"),
        "priority_functions": (existing_scan.get("function_scores") or {}).get("top") or priority_functions[:20],
        "named_priority_functions": priority_functions[:20],
        "suspicious_paths": existing_scan.get("suspicious_paths") or [],
        "behavior_chains": existing_scan.get("behavior_chains") or [],
        "behavioral_imports": behavioral_imports,
        "suspicious_strings": [
            {
                "string": str(item.get("string", ""))[:160],
                "address": hex(item.get("vaddr", 0)) if isinstance(item.get("vaddr"), int) else item.get("address"),
                "reason": item.get("reason"),
            }
            for item in suspicious_strings[:30]
        ],
        "string_xrefs": xrefs,
        "notes": notes,
    }
