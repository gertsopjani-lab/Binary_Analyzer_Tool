#!/usr/bin/env python3
"""Defensive Binary Vulnerability Reporter.

Drop a Windows PE or ELF binary path into the chat UI and get a structured
static risk report. The deterministic analysis lives under tools/; this file
only handles OpenAI Agents SDK wiring and the terminal interface.
"""

import json
import os
import re
import shlex
import sys
import time
from contextlib import nullcontext

_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
_removed_import_paths = []
for _path in ("", _PROJECT_DIR):
    while _path in sys.path:
        sys.path.remove(_path)
        _removed_import_paths.append(_path)
try:
    from agents import Agent, Runner, SQLiteSession, function_tool
    try:
        from agents import ModelSettings
    except ImportError:  # Older Agents SDK versions may not expose this.
        ModelSettings = None
finally:
    for _path in reversed(_removed_import_paths):
        sys.path.insert(0, _path)
from dotenv import load_dotenv

from tools.paths import detect_format, resolve_path, wsl_path
from tools.pe_analysis import pe_scan
from tools.reporting import run_full_pipeline
from tools.static_analysis import (
    analyze_reverse_engineering,
    decompile_function,
    extract_symbols,
    find_strings,
    list_functions,
    run_checksec,
    scan_embedded_secrets,
)
from tools.ui import RICH_AVAILABLE, console, render_message, render_welcome

load_dotenv()


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"


CURRENT_BINARY = None

ACTIVE_SCAN = {
    "path": None,
    "pipeline": None,
    "metadata": None,
    "strings": None,
    "suspicious_strings": None,
    "imports": None,
    "protections": None,
    "findings": None,
    "fixes": None,
    "re_leads": None,
    "functions": None,
    "sections": None,
    "entropy": None,
    "xrefs": None,
    "callgraph": None,
    "capabilities": None,
    "packed": None,
    "yara_matches": None,
    "behavior_scores": None,
    "function_clusters": None,
    "analysis_graph": None,
    "function_scores": None,
    "suspicious_paths": None,
    "behavior_chains": None,
    "additional_observations": None,
    "confidence_scores": None,
    "deduplicated_findings": None,
    "last_topic": None,
    "last_finding": None,
    "agent_outputs": {},
}

SCAN_HISTORY = []

SUSPICIOUS_STRING_PATTERN = (
    "password|token|secret|license|"
    "key|api|auth|http|https|debug|"
    "wallet|private|hook|inject"
)


def _truncate(value, limit=2000):
    text = value if isinstance(value, str) else json.dumps(value, indent=2, default=str)
    return text if len(text) <= limit else text[:limit] + "\n... [truncated]"


def _reset_active_scan():
    global CURRENT_BINARY
    CURRENT_BINARY = None
    for key in ACTIVE_SCAN:
        ACTIVE_SCAN[key] = None
    ACTIVE_SCAN["agent_outputs"] = {}
    SCAN_HISTORY.clear()


def _set_last_topic(topic: str):
    ACTIVE_SCAN["last_topic"] = topic


def _cache_agent_output(topic: str, output: str):
    if not isinstance(ACTIVE_SCAN.get("agent_outputs"), dict):
        ACTIVE_SCAN["agent_outputs"] = {}
    outputs = ACTIVE_SCAN["agent_outputs"]
    outputs[topic] = str(output)


def _active_name() -> str:
    path = ACTIVE_SCAN.get("path") or CURRENT_BINARY
    return os.path.basename(path) if path else "no-target"


def _require_active() -> str | None:
    path = ACTIVE_SCAN.get("path") or CURRENT_BINARY
    if not path:
        chat_print("No active binary. Use scan <path> first.", C.YELLOW, "!")
        return None
    return path


def _cache_pipeline_result(path: str, result: dict):
    global CURRENT_BINARY
    CURRENT_BINARY = path
    ACTIVE_SCAN["path"] = path
    ACTIVE_SCAN["pipeline"] = result
    scan = result.get("scan") or {}
    symbols = scan.get("symbols") or {}
    re_leads = scan.get("reverse_engineering") or {}
    secrets = scan.get("secrets") or {}

    ACTIVE_SCAN["metadata"] = {
        "format": scan.get("format"),
        "architecture": scan.get("architecture"),
        "file_size": scan.get("file_size") or secrets.get("file_size"),
        "entry_point": (scan.get("architecture") or {}).get("entry_point"),
    }
    ACTIVE_SCAN["strings"] = scan.get("strings")
    ACTIVE_SCAN["suspicious_strings"] = _collect_suspicious_strings(scan)
    ACTIVE_SCAN["imports"] = {
        "imports": symbols.get("imports") or symbols.get("plt_imports") or [],
        "dangerous_functions": symbols.get("dangerous_functions") or [],
        "review_functions": symbols.get("review_functions") or [],
        "behavioral_imports": symbols.get("behavioral_imports") or {},
        "win_functions": symbols.get("win_functions") or {},
    }
    ACTIVE_SCAN["protections"] = scan.get("protections")
    ACTIVE_SCAN["findings"] = result.get("findings") or []
    ACTIVE_SCAN["deduplicated_findings"] = scan.get("deduplicated_findings") or result.get("findings") or []
    ACTIVE_SCAN["confidence_scores"] = scan.get("confidence_scores") or {}
    ACTIVE_SCAN["fixes"] = [item for item in (result.get("findings") or []) if item.get("risk") in {"HIGH", "MEDIUM"}]
    ACTIVE_SCAN["re_leads"] = re_leads
    ACTIVE_SCAN["functions"] = scan.get("functions") or re_leads.get("priority_functions") or symbols.get("interesting_functions") or []
    ACTIVE_SCAN["sections"] = scan.get("sections")
    ACTIVE_SCAN["entropy"] = [
        section for section in (scan.get("sections") or []) if section.get("entropy") is not None
    ]
    ACTIVE_SCAN["xrefs"] = scan.get("xrefs")
    ACTIVE_SCAN["callgraph"] = scan.get("callgraph")
    ACTIVE_SCAN["capabilities"] = scan.get("capabilities")
    ACTIVE_SCAN["packed"] = scan.get("packed")
    ACTIVE_SCAN["yara_matches"] = scan.get("yara_matches")
    ACTIVE_SCAN["behavior_scores"] = scan.get("behavior_scores")
    ACTIVE_SCAN["function_clusters"] = scan.get("function_clusters")
    ACTIVE_SCAN["analysis_graph"] = scan.get("analysis_graph")
    ACTIVE_SCAN["function_scores"] = scan.get("function_scores")
    ACTIVE_SCAN["suspicious_paths"] = scan.get("suspicious_paths")
    ACTIVE_SCAN["behavior_chains"] = scan.get("behavior_chains")
    ACTIVE_SCAN["additional_observations"] = scan.get("additional_observations")
    ACTIVE_SCAN["agent_outputs"] = {}
    ACTIVE_SCAN["last_topic"] = "summary"
    ACTIVE_SCAN["last_finding"] = None
    if not SCAN_HISTORY or SCAN_HISTORY[-1] != path:
        SCAN_HISTORY.append(path)


def _collect_suspicious_strings(scan: dict) -> list[str]:
    values = []
    interesting = (scan.get("strings") or {}).get("interesting") or {}
    for matches in interesting.values():
        if isinstance(matches, list):
            values.extend(str(item) for item in matches)

    re_summary = scan.get("reverse_engineering") or {}
    for item in re_summary.get("suspicious_strings") or []:
        text = item.get("string") if isinstance(item, dict) else str(item)
        if text:
            values.append(str(text))

    secrets = scan.get("secrets") or {}
    for matches in (secrets.get("findings") or {}).values():
        if isinstance(matches, list):
            values.extend(str(item) for item in matches)
    values.extend(str(item) for item in (secrets.get("keyword_hits") or []))

    seen = set()
    out = []
    pattern = re.compile(SUSPICIOUS_STRING_PATTERN, re.I)
    for value in values:
        clean = value.strip()
        if not clean or clean in seen:
            continue
        if pattern.search(clean) or re.search(r"(?i)flag|ctf|wrong|correct", clean):
            seen.add(clean)
            out.append(clean[:220])
        if len(out) >= 80:
            break
    return out


def _cache_tool_result(topic: str, payload: dict):
    if topic == "strings":
        ACTIVE_SCAN["strings"] = payload
        ACTIVE_SCAN["suspicious_strings"] = _collect_suspicious_strings({"strings": payload})
    elif topic == "imports":
        ACTIVE_SCAN["imports"] = {
            "imports": payload.get("imports") or payload.get("plt_imports") or [],
            "dangerous_functions": payload.get("dangerous_functions") or [],
            "review_functions": payload.get("review_functions") or [],
            "behavioral_imports": payload.get("behavioral_imports") or {},
            "win_functions": payload.get("win_functions") or {},
        }
    elif topic == "protections":
        ACTIVE_SCAN["protections"] = payload
    elif topic == "metadata":
        ACTIVE_SCAN["metadata"] = payload
        ACTIVE_SCAN["sections"] = payload.get("sections")
        ACTIVE_SCAN["protections"] = payload.get("protections") or ACTIVE_SCAN.get("protections")
    elif topic == "secrets":
        ACTIVE_SCAN["suspicious_strings"] = _collect_suspicious_strings({"secrets": payload})
    elif topic == "re_leads":
        ACTIVE_SCAN["re_leads"] = payload
        ACTIVE_SCAN["functions"] = payload.get("priority_functions") or ACTIVE_SCAN.get("functions")
    elif topic == "functions":
        ACTIVE_SCAN["functions"] = payload.get("functions") or payload
    _set_last_topic(topic)


def _normalize_query_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()


def _finding_terms(finding: dict) -> set[str]:
    flag = _normalize_query_text(finding.get("flag", ""))
    status = _normalize_query_text(finding.get("status", ""))
    words = set(flag.split()) | set(status.split())
    phrases = {flag, status}
    aliases = {
        "No Stack Canary": {"canary", "stack canary", "cookie", "stack cookie"},
        "Dangerous C-runtime calls": {"dangerous calls", "risky imports", "crt", "gets", "strcpy", "scanf"},
        "Memory/input routines need review": {"memory routines", "input routines", "review calls", "memcpy", "printf"},
        "Hardcoded secrets / license data": {"secrets", "license", "tokens", "passwords", "keys", "hardcoded"},
        "Suspicious embedded strings": {"embedded strings", "strings", "suspicious strings"},
        "No DEP / NX": {"nx", "dep", "executable stack"},
        "No ASLR / PIE": {"aslr", "pie", "dynamicbase"},
        "No RELRO": {"relro", "got"},
        "Partial RELRO": {"relro", "got"},
        "No Control Flow Guard": {"cfg", "control flow guard"},
        "SEH records present": {"seh", "exception handler"},
        "Reverse-engineering leads": {"re leads", "reverse engineering", "functions", "xrefs"},
    }
    phrases |= aliases.get(finding.get("flag", ""), set())
    return {term for term in phrases | words if term}


def _match_finding_from_text(text: str) -> dict | None:
    findings = ACTIVE_SCAN.get("findings") or []
    if not findings:
        return None

    normalized = _normalize_query_text(text)
    best = None
    best_score = 0
    for finding in findings:
        score = 0
        for term in _finding_terms(finding):
            clean = _normalize_query_text(term)
            if not clean:
                continue
            if clean in normalized:
                score += 4 if " " in clean else 1
        flag_words = set(_normalize_query_text(finding.get("flag", "")).split())
        query_words = set(normalized.split())
        score += len(flag_words & query_words)
        if score > best_score:
            best = finding
            best_score = score
    return best if best_score >= 2 else None


def _agent_for_finding(finding: dict):
    flag = str(finding.get("flag", "")).lower()
    status = str(finding.get("status", "")).lower()
    combined = f"{flag} {status}"
    if any(term in combined for term in ("secret", "license", "token", "password", "key")):
        return secrets_agent
    if any(term in combined for term in ("string", "embedded")):
        return strings_agent
    if any(term in combined for term in ("dangerous", "runtime", "memory/input", "import", "crt", "gets", "strcpy", "printf", "memcpy")):
        return symbols_agent
    if any(term in combined for term in ("reverse", "re lead", "xref", "function")):
        return re_agent
    if any(term in combined for term in ("cfg", "seh")):
        return pe_scanner_agent
    if any(term in combined for term in ("nx", "dep", "aslr", "pie", "canary", "relro", "protection")):
        return scanner_agent
    if any(term in combined for term in ("entropy", "section", "packed")):
        return pe_scanner_agent if detect_format(ACTIVE_SCAN.get("path") or "") == "PE" else metadata_agent
    return analyzer_agent


def _resolve_or_error(binary_path: str) -> tuple[str | None, str | None]:
    resolved, found = resolve_path(binary_path)
    if not found:
        return None, json.dumps({"error": f"File not found: {binary_path}"})
    return resolved, None


@function_tool
def tool_checksec(binary_path: str) -> str:
    """Check NX, PIE, canary, RELRO, ASLR on an ELF or PE binary."""
    resolved, error = _resolve_or_error(binary_path)
    if error:
        return error
    if detect_format(resolved) == "PE":
        result = pe_scan(resolved)
        payload = result.get("protections", result)
    else:
        payload = run_checksec(resolved)
    _cache_tool_result("protections", payload)
    return json.dumps(payload, default=str)


@function_tool
def tool_extract_symbols(binary_path: str) -> str:
    """Extract imports, exports, risky calls, review calls, and named RE leads."""
    resolved, error = _resolve_or_error(binary_path)
    if error:
        return error
    if detect_format(resolved) == "PE":
        result = pe_scan(resolved)
        payload = result.get("symbols", result)
    else:
        payload = extract_symbols(resolved)
    _cache_tool_result("imports", payload)
    return json.dumps(payload, default=str)


@function_tool
def tool_find_strings(binary_path: str, pattern: str = "") -> str:
    """Extract printable strings. Optionally filter by regex pattern."""
    resolved, error = _resolve_or_error(binary_path)
    if error:
        return error
    kwargs = {"binary_path": resolved}
    if pattern:
        kwargs["pattern"] = pattern
    payload = find_strings(**kwargs)
    _cache_tool_result("strings", payload)
    return json.dumps(payload, default=str)


@function_tool
def tool_scan_secrets(binary_path: str) -> str:
    """Scan for embedded flags, passwords, API keys, private keys, URLs, and tokens."""
    resolved, error = _resolve_or_error(binary_path)
    if error:
        return error
    payload = scan_embedded_secrets(resolved)
    _cache_tool_result("secrets", payload)
    return json.dumps(payload, default=str)


@function_tool
def tool_decompile(binary_path: str, function_name: str = "main") -> str:
    """Decompile a named function to pseudo-C, falling back to disassembly."""
    resolved, error = _resolve_or_error(binary_path)
    if error:
        return error
    return json.dumps(decompile_function(resolved, function_name), default=str)


@function_tool
def tool_pe_scan(binary_path: str) -> str:
    """Run Windows PE analysis: protections, imports, strings, and section entropy."""
    resolved, error = _resolve_or_error(binary_path)
    if error:
        return error
    return json.dumps(pe_scan(resolved), default=str)


@function_tool
def tool_list_functions(binary_path: str) -> str:
    """List discovered functions and likely validation/secret-handling names."""
    resolved, error = _resolve_or_error(binary_path)
    if error:
        return error
    payload = list_functions(resolved)
    _cache_tool_result("functions", payload)
    return json.dumps(payload, default=str)


@function_tool
def tool_reverse_engineering_leads(binary_path: str) -> str:
    """Find likely RE starting points: suspicious functions, imports, strings, and xrefs."""
    resolved, error = _resolve_or_error(binary_path)
    if error:
        return error
    payload = analyze_reverse_engineering(resolved)
    _cache_tool_result("re_leads", payload)
    return json.dumps(payload, default=str)


@function_tool
def tool_read_file_metadata(binary_path: str) -> str:
    """Identify binary format, size, architecture, entry point, sections, and protections."""
    resolved, error = _resolve_or_error(binary_path)
    if error:
        return error

    fmt = detect_format(resolved)
    meta = {
        "binary": resolved,
        "name": os.path.basename(resolved),
        "format": fmt,
        "file_size": os.path.getsize(resolved),
    }
    if fmt == "PE":
        scan = pe_scan(resolved)
        if "error" in scan:
            meta["error"] = scan["error"]
        else:
            meta["architecture"] = scan.get("architecture", {})
            meta["protections"] = scan.get("protections", {})
            meta["sections"] = scan.get("sections", [])[:12]
    elif fmt == "ELF":
        protections = run_checksec(resolved)
        symbols = extract_symbols(resolved)
        meta["architecture"] = {
            "arch": symbols.get("arch", protections.get("arch", "?")),
            "bits": symbols.get("bits", protections.get("bits", "?")),
            "entry_point": symbols.get("entry_point", "?"),
        }
        meta["protections"] = {k: protections.get(k, "unknown") for k in ("nx", "pie", "canary", "relro", "aslr")}
        if "error" in protections:
            meta["protection_error"] = protections["error"]
        if "error" in symbols:
            meta["symbol_error"] = symbols["error"]
    _cache_tool_result("metadata", meta)
    return json.dumps(meta, default=str)


@function_tool
def tool_full_pipeline(binary_path: str) -> str:
    """Run the full defensive scan and return the formatted report plus structured data."""
    resolved, error = _resolve_or_error(binary_path)
    if error:
        return error
    result = run_full_pipeline(resolved)
    _cache_pipeline_result(resolved, result)
    findings = result.get("findings", [])
    compact_findings = [
        {
            "risk": item.get("risk"),
            "flag": item.get("flag"),
            "status": item.get("status"),
            "fix": item.get("fix"),
        }
        for item in findings[:12]
    ]
    re_summary = result.get("scan", {}).get("reverse_engineering", {}) or {}
    return json.dumps(
        {
            "overall_risk": result.get("overall_risk"),
            "top_priority_fix": result.get("top_priority_fix"),
            "scan_time_ms": result.get("scan_time_ms"),
            "format": result.get("scan", {}).get("format"),
            "findings": compact_findings,
            "packed": result.get("scan", {}).get("packed"),
            "behavior_scores": result.get("scan", {}).get("behavior_scores"),
            "capability_groups": (result.get("scan", {}).get("capabilities") or {}).get("groups"),
            "xrefs": {
                "strings": (result.get("scan", {}).get("xrefs") or {}).get("strings", [])[:8],
                "imports": (result.get("scan", {}).get("xrefs") or {}).get("imports", [])[:8],
            },
            "callgraph_stats": (result.get("scan", {}).get("callgraph") or {}).get("stats"),
            "analysis_graph_stats": (result.get("scan", {}).get("analysis_graph") or {}).get("stats"),
            "top_suspicious_functions": (result.get("scan", {}).get("function_scores") or {}).get("top", [])[:8],
            "suspicious_paths": (result.get("scan", {}).get("suspicious_paths") or [])[:8],
            "behavior_chains": (result.get("scan", {}).get("behavior_chains") or [])[:8],
            "reverse_engineering": {
                "priority_functions": (re_summary.get("priority_functions") or [])[:8],
                "behavioral_imports": dict(list((re_summary.get("behavioral_imports") or {}).items())[:8])
                if isinstance(re_summary.get("behavioral_imports"), dict)
                else {},
                "suspicious_strings": (re_summary.get("suspicious_strings") or [])[:8],
                "notes": (re_summary.get("notes") or [])[:4],
            },
            "note": "Full terminal report is rendered locally by the CLI for direct scan/load/analyze path inputs.",
        },
        default=str,
    )


@function_tool
def tool_trace_execution_paths(binary_path: str) -> str:
    """Return ranked graph execution paths and top suspicious functions."""
    resolved, error = _resolve_or_error(binary_path)
    if error:
        return error
    if ACTIVE_SCAN.get("path") == resolved and ACTIVE_SCAN.get("suspicious_paths") is not None:
        scan = (ACTIVE_SCAN.get("pipeline") or {}).get("scan") or {}
    else:
        result = run_full_pipeline(resolved)
        _cache_pipeline_result(resolved, result)
        scan = result.get("scan") or {}
    return json.dumps(
        {
            "graph_stats": (scan.get("analysis_graph") or {}).get("stats"),
            "entry_candidates": (scan.get("analysis_graph") or {}).get("entry_candidates"),
            "top_functions": (scan.get("function_scores") or {}).get("top", [])[:20],
            "suspicious_paths": (scan.get("suspicious_paths") or [])[:20],
            "behavior_chains": (scan.get("behavior_chains") or [])[:20],
            "string_provenance": dict(list(((scan.get("analysis_graph") or {}).get("string_provenance") or {}).items())[:20]),
        },
        default=str,
    )


MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")


def _agent_settings(max_tokens: int) -> dict:
    if ModelSettings is None:
        return {}  # TODO: cap max_tokens when SDK supports ModelSettings.
    try:
        return {"model_settings": ModelSettings(max_tokens=max_tokens)}
    except TypeError:
        return {}  # TODO: cap max_tokens when SDK supports ModelSettings(max_tokens=...).


metadata_agent = Agent(
    name="MetadataAgent",
    model=MODEL,
    tools=[tool_read_file_metadata],
    instructions=(
        "Use tool_read_file_metadata to identify format, architecture, size, entry point, "
        "sections, and protection flags. Never execute the binary. Hand back to Orchestrator."
    ),
    **_agent_settings(400),
)

scanner_agent = Agent(
    name="ScannerAgent",
    model=MODEL,
    tools=[tool_checksec],
    instructions=(
        "Use tool_checksec to read hardening flags. Explain each missing protection in plain "
        "English and give concrete compiler or linker flags. Hand back to Orchestrator."
    ),
    **_agent_settings(400),
)

symbols_agent = Agent(
    name="SymbolsAgent",
    model=MODEL,
    tools=[tool_extract_symbols],
    instructions=(
        "Use tool_extract_symbols to list imports, exports, high-risk calls, review-only calls, "
        "and named functions. Do not claim review-only calls are exploitable without call-site evidence."
    ),
    **_agent_settings(600),
)

strings_agent = Agent(
    name="StringsAgent",
    model=MODEL,
    tools=[tool_find_strings],
    instructions=(
        "Use tool_find_strings to surface license keys, passwords, URLs, paths, debug text, "
        "challenge strings, and custom pattern matches. Explain why extracted strings matter."
    ),
    **_agent_settings(600),
)

secrets_agent = Agent(
    name="SecretsAgent",
    model=MODEL,
    tools=[tool_scan_secrets],
    instructions=(
        "Use tool_scan_secrets to find embedded secrets. Explain that shipped client-side "
        "secrets can be extracted without running the binary and give concrete remediation."
    ),
    **_agent_settings(600),
)

decompile_agent = Agent(
    name="DecompileAgent",
    model=MODEL,
    tools=[tool_decompile],
    instructions=(
        "Use tool_decompile for a named function. Summarize what the function appears to do, "
        "which call sites or strings support that reading, and what the developer should fix."
    ),
    **_agent_settings(800),
)

re_agent = Agent(
    name="ReverseEngineeringAgent",
    model=MODEL,
    tools=[tool_list_functions, tool_reverse_engineering_leads, tool_trace_execution_paths, tool_decompile],
    instructions=(
        "Find RE starting points before decompiling blindly. Never give generic statements. "
        "Always cite concrete function names, strings, imports, graph paths, and xrefs from tools."
    ),
    **_agent_settings(600),
)

pe_scanner_agent = Agent(
    name="PEScannerAgent",
    model=MODEL,
    tools=[tool_pe_scan],
    instructions=(
        "Use tool_pe_scan for Windows PE data: DEP, ASLR, CFG, SecurityCookie, SEH, imports, "
        "behavioral APIs, strings, and section entropy. Report evidence from this binary only."
    ),
    **_agent_settings(400),
)

analyzer_agent = Agent(
    name="AnalyzerAgent",
    model=MODEL,
    tools=[tool_full_pipeline],
    instructions=(
        "Use tool_full_pipeline for default binary-path requests. Render the returned report "
        "exactly, then add a short note naming the first hardening action and the best graph-backed RE lead."
    ),
    **_agent_settings(800),
)

orchestrator = Agent(
    name="Orchestrator",
    model=MODEL,
    handoffs=[
        metadata_agent,
        scanner_agent,
        symbols_agent,
        strings_agent,
        secrets_agent,
        decompile_agent,
        re_agent,
        pe_scanner_agent,
        analyzer_agent,
    ],
    instructions=(
        "Defensive binary analysis assistant. Static analysis only - never run the binary "
        "or craft exploits.\n"
        "- Binary path given -> hand off to AnalyzerAgent.\n"
        "- RE / functions / xrefs -> ReverseEngineeringAgent.\n"
        "- Specific function -> DecompileAgent.\n"
        "Use only tool evidence. Never say 'may be vulnerable' without naming the exact function/import/string/path. "
        "Separate high-risk APIs from review-only APIs. "
        "State tool limitations when relevant. Render full pipeline reports verbatim."
    ),
    **_agent_settings(500),
)


def chat_print(text, color=None, prefix=">"):
    if RICH_AVAILABLE:
        render_message(str(text), prefix=prefix)
        return
    color = color or C.CYAN
    print(f"\n{color}{C.BOLD}{text}{C.RESET}\n")


def chat_input(prompt=None):
    prompt = prompt or f"  [{_active_name()}] You > "
    try:
        return input(f"{C.GREEN}{C.BOLD}{prompt}{C.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        chat_print("Goodbye.", C.YELLOW)
        sys.exit(0)


def show_welcome():
    agents = [
        ("MetadataAgent", "format, architecture, entry point, file size"),
        ("ScannerAgent", "NX / PIE / canary / RELRO / ASLR flags"),
        ("SymbolsAgent", "imports, exports, risky calls, review calls"),
        ("StringsAgent", "printable strings and pattern search"),
        ("SecretsAgent", "embedded keys, passwords, tokens"),
        ("DecompileAgent", "pseudo-C or disassembly for a named function"),
        ("ReverseEngineeringAgent", "functions, xrefs, behavioral imports, RE leads"),
        ("PEScannerAgent", "Windows PE specialist"),
        ("AnalyzerAgent", "one-shot structured risk report"),
    ]
    if RICH_AVAILABLE:
        render_welcome(agents)
        return
    print()
    print(f"{C.CYAN}{C.BOLD}{'=' * 60}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}   DEFENSIVE BINARY VULNERABILITY REPORTER{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'=' * 60}{C.RESET}")
    print()
    print(f"  {C.BLUE}Active agents:{C.RESET}")
    for name, desc in agents:
        print(f"    {C.PURPLE}-{C.RESET} {C.BOLD}{name:24}{C.RESET} {desc}")
    print()
    print(f"  {C.BLUE}Drop an .exe or ELF path to get a risk report with concrete fixes.{C.RESET}")
    print(f"  {C.BLUE}Use 'scan <path>', 'load <path>', or ask for RE leads / decompile <function>.{C.RESET}")
    print()


def _rewrite_path_shortcut(user_input: str) -> str:
    if re.match(r"^[a-zA-Z]:[/\\]", user_input):
        resolved, found = resolve_path(user_input)
        path = resolved if found else wsl_path(user_input)
        return f"Analyze this binary for vulnerabilities and produce a risk report: {path}"

    for kw in ("load ", "scan ", "analyze "):
        if user_input.lower().startswith(kw):
            raw = user_input[len(kw):].strip()
            resolved, found = resolve_path(raw)
            path = resolved if found else wsl_path(raw)
            return f"Analyze this binary for vulnerabilities and produce a risk report: {path}"
    return user_input


def _direct_scan_path(user_input: str) -> str | None:
    stripped = user_input.strip()
    unquoted = stripped.strip('"').strip("'")
    if re.match(r"^[a-zA-Z]:[/\\]", unquoted) or unquoted.startswith(("/", "./", "../")):
        resolved, found = resolve_path(unquoted)
        return resolved if found else None

    for kw in ("load ", "scan ", "analyze "):
        if stripped.lower().startswith(kw):
            raw = stripped[len(kw):].strip().strip('"').strip("'")
            resolved, found = resolve_path(raw)
            return resolved if found else None
    return None


def _split_command(text: str) -> list[str]:
    try:
        return [part.strip('"').strip("'") for part in shlex.split(text, posix=False)]
    except ValueError:
        return text.split()


def _path_from_command(text: str) -> str | None:
    stripped = text.strip()
    lower = stripped.lower()
    for kw in ("scan", "load", "analyze"):
        if lower == kw:
            return None
        if lower.startswith(kw + " "):
            raw = stripped[len(kw):].strip().strip('"').strip("'")
            resolved, found = resolve_path(raw)
            return resolved if found else raw
    return _direct_scan_path(text)


def _parse_command(user_input: str) -> dict:
    text = user_input.strip()
    lower = text.lower().strip()
    if lower in {"help", "h", "?"}:
        return {"type": "help"}
    if lower in {"clear session", "clear", "reset"}:
        return {"type": "clear"}
    if lower in {"active target", "target", "active", "history"}:
        return {"type": "active"}

    path = _path_from_command(text)
    if path:
        return {"type": "scan", "path": path}

    shortcuts = {
        "s": "suspicious_strings",
        "i": "imports",
        "r": "re_leads",
        "p": "protections",
        "m": "metadata",
        "f": "findings",
        "x": "xrefs",
    }
    if lower in shortcuts:
        return {"type": "topic", "topic": shortcuts[lower]}

    if lower.startswith("decompile "):
        func = text.split(None, 1)[1].strip()
        return {"type": "decompile", "function": func or "main"}

    if re.search(r"\b(where is .* used|trace .*string|trace references|show callers|called by|caller|callee|call graph|callgraph)\b", lower):
        if re.search(r"\b(path|execution|entry|chain|trace)\b", lower):
            return {"type": "topic", "topic": "execution_paths", "refresh": True}
        return {"type": "topic", "topic": "xrefs" if "string" in lower or "reference" in lower or "used" in lower else "callgraph", "refresh": True}

    if re.search(r"\b(why is .*suspicious|evidence chain|why suspicious|confidence)\b", lower):
        return {"type": "topic", "topic": "evidence", "refresh": True}

    vulnerability_detail = re.search(
        r"\b(more|tell me more|show me more|go deeper|expand|detail|details|elaborate|could find more)\b",
        lower,
    ) and re.search(r"\b(vulnerability|finding|issue|risk|bug|weakness|about)\b", lower)
    if vulnerability_detail:
        finding = _match_finding_from_text(text)
        if finding:
            return {"type": "finding", "finding": finding, "refresh": True}
        if ACTIVE_SCAN.get("last_finding"):
            return {"type": "finding", "finding": ACTIVE_SCAN["last_finding"], "refresh": True}

    topic_patterns = [
        ("suspicious_strings", r"\b(suspicious strings|embedded strings|strings|those strings)\b"),
        ("imports", r"\b(imports|risky calls|dangerous calls|crt|api calls|that import)\b"),
        ("protections", r"\b(protections|checksec|nx|dep|pie|aslr|canary|relro|cfg|seh)\b"),
        ("metadata", r"\b(metadata|file info|binary info|header|entry point|architecture|arch)\b"),
        ("functions", r"\b(functions|function list|symbols)\b"),
        ("xrefs", r"\b(xrefs|cross refs|cross references|references)\b"),
        ("callgraph", r"\b(callgraph|call graph|callers|callees|called by|execution paths|entrypoint trace)\b"),
        ("analysis_graph", r"\b(analysis graph|graph|graph stats|provenance)\b"),
        ("execution_paths", r"\b(execution paths|suspicious paths|api chain|api chains|entrypoint trace|trace execution)\b"),
        ("behavior_chains", r"\b(behavior chains|behavior chain|api sequence|api sequences|dynamic api resolution)\b"),
        ("function_scores", r"\b(function scores|suspicious functions|top functions|rank functions)\b"),
        ("capabilities", r"\b(capabilities|capa|behavior scores|behavioral score|yara)\b"),
        ("packed", r"\b(packed|packing|obfuscated|upx)\b"),
        ("evidence", r"\b(evidence|confidence|why suspicious|why is this suspicious)\b"),
        ("re_leads", r"\b(re leads|reverse engineering|follow that lead|continue re)\b"),
        ("findings", r"\b(findings|vulnerabilities|vulns|issues)\b"),
        ("fixes", r"\b(fixes|mitigations|recommendations|top priority)\b"),
        ("secrets", r"\b(secrets|tokens|passwords|keys|api keys|private)\b"),
        ("sections", r"\b(sections|section table)\b"),
        ("entropy", r"\b(entropy|packed|packing|suspicious sections)\b"),
    ]
    refresh_pattern = r"\b(more|tell me more|go deeper|show me more about|more about|expand|detail|details|elaborate)\b"
    if re.search(refresh_pattern, lower):
        for topic, pattern in topic_patterns:
            if re.search(pattern, lower):
                return {"type": "topic", "topic": topic, "refresh": True}

    for topic, pattern in topic_patterns:
        if re.search(pattern, lower):
            return {"type": "topic", "topic": topic}

    if re.search(r"\b(continue|go deeper|tell me more|go on|more|analyze that|expand on that)\b", lower):
        return {"type": "topic", "topic": ACTIVE_SCAN.get("last_topic") or "re_leads", "refresh": True}

    return {"type": "ambiguous", "text": text}


def _render_help():
    target = ACTIVE_SCAN.get("path") or "none"
    help_text = f"""
Active target: {target}

Commands:
  scan <path> | analyze <path> | load <path>
  show suspicious strings | show imports | show risky calls
  show findings | show fixes | show secrets
  show metadata | show protections | show RE leads
  show functions | show entropy | show sections | show xrefs
  show callgraph | show analysis graph | show suspicious paths
  show behavior chains | show function scores | show capabilities | show packed | show evidence
  decompile <function>
  active target | clear session | help

Shortcuts:
  s = suspicious strings
  i = imports
  r = RE leads
  p = protections
  m = metadata
  f = findings
  x = xrefs

Examples:
  scan "C:\\path\\CrackMe v2.exe"
  show suspicious strings
  decompile main
  go deeper into those strings
""".strip()
    chat_print(help_text, prefix="help")


def _render_active():
    lines = [f"Active target: {ACTIVE_SCAN.get('path') or 'none'}"]
    if ACTIVE_SCAN.get("last_topic"):
        lines.append(f"Last topic: {ACTIVE_SCAN['last_topic']}")
    if SCAN_HISTORY:
        lines.append("History:")
        lines.extend(f"  - {path}" for path in SCAN_HISTORY[-5:])
    chat_print("\n".join(lines), prefix="target")


def _render_kv(title: str, value):
    chat_print(_truncate(value), prefix=title)


def _render_cached_topic(topic: str) -> bool:
    path = _require_active()
    if not path:
        return True

    _set_last_topic(topic)
    cached_output = (ACTIVE_SCAN.get("agent_outputs") or {}).get(topic)
    if cached_output:
        chat_print(cached_output, prefix=topic)
        return True

    if topic == "suspicious_strings":
        values = ACTIVE_SCAN.get("suspicious_strings") or []
        if not values:
            return False
        xref_by_value = (ACTIVE_SCAN.get("xrefs") or {}).get("by_value") or {}
        behavior = ACTIVE_SCAN.get("behavior_scores") or {}
        lines = ["Suspicious / high-signal strings:"]
        for idx, item in enumerate(values[:60], 1):
            refs = xref_by_value.get(item) or []
            suffix = f" | xrefs: {', '.join(str(r.get('function')) for r in refs[:3])}" if refs else ""
            if behavior.get("clusters"):
                suffix += f" | related behavior: {', '.join(list(behavior.get('clusters').keys())[:3])}"
            lines.append(f"{idx:02d}. {item}{suffix}")
        _render_kv("strings", "\n".join(lines))
        _cache_agent_output(topic, "\n".join(lines))
        return True

    if topic == "imports":
        imports = ACTIVE_SCAN.get("imports") or {}
        if not imports:
            return False
        lines = ["Imports and risky calls:"]
        for label in ("dangerous_functions", "review_functions", "behavioral_imports", "win_functions", "imports"):
            values = imports.get(label)
            if not values:
                continue
            lines.append(f"\n{label}:")
            if isinstance(values, dict):
                lines.extend(f"  - {k}: {v}" for k, v in list(values.items())[:40])
            else:
                lines.extend(f"  - {item}" for item in list(values)[:80])
        _render_kv("imports", "\n".join(lines))
        _cache_agent_output(topic, "\n".join(lines))
        return True

    if topic == "protections":
        if not ACTIVE_SCAN.get("protections"):
            return False
        _render_kv("protections", ACTIVE_SCAN["protections"])
        _cache_agent_output(topic, _truncate(ACTIVE_SCAN["protections"]))
        return True

    if topic == "metadata":
        if not ACTIVE_SCAN.get("metadata"):
            return False
        _render_kv("metadata", ACTIVE_SCAN["metadata"])
        _cache_agent_output(topic, _truncate(ACTIVE_SCAN["metadata"]))
        return True

    if topic == "findings":
        findings = ACTIVE_SCAN.get("deduplicated_findings") or ACTIVE_SCAN.get("findings") or []
        if not findings:
            return False
        lines = ["Findings:"]
        for item in findings:
            lines.append(f"\n[{item.get('risk')}] {item.get('flag')} (confidence {float(item.get('confidence') or 0):.2f}, source={item.get('source')})")
            lines.append(f"  Evidence: {item.get('status')}")
            for ev in (item.get("evidence") or [])[:5]:
                lines.append(f"    - {ev}")
            lines.append(f"  Why: {item.get('human')}")
        _render_kv("findings", "\n".join(lines))
        _cache_agent_output(topic, "\n".join(lines))
        return True

    if topic == "fixes":
        fixes = ACTIVE_SCAN.get("fixes") or ACTIVE_SCAN.get("findings") or []
        if not fixes:
            return False
        lines = ["Recommended fixes:"]
        for idx, item in enumerate(fixes[:20], 1):
            lines.append(f"{idx:02d}. [{item.get('risk')}] {item.get('flag')}: {item.get('fix')}")
        _render_kv("fixes", "\n".join(lines))
        _cache_agent_output(topic, "\n".join(lines))
        return True

    if topic == "re_leads":
        leads = ACTIVE_SCAN.get("re_leads") or {}
        if not leads:
            return False
        _render_kv("re-leads", leads)
        _cache_agent_output(topic, _truncate(leads))
        return True

    if topic == "functions":
        functions = ACTIVE_SCAN.get("functions") or []
        if not functions:
            return False
        lines = ["Priority / discovered functions:"]
        for func in functions[:80]:
            if isinstance(func, dict):
                lines.append(f"  - {func.get('name', '?')} {func.get('offset') or func.get('address') or ''}")
            else:
                lines.append(f"  - {func}")
        _render_kv("functions", "\n".join(lines))
        _cache_agent_output(topic, "\n".join(lines))
        return True

    if topic == "sections":
        sections = ACTIVE_SCAN.get("sections") or []
        if not sections:
            return False
        _render_kv("sections", sections[:30])
        _cache_agent_output(topic, _truncate(sections[:30]))
        return True

    if topic == "entropy":
        entropy = ACTIVE_SCAN.get("entropy") or []
        if not entropy:
            return False
        suspicious = [item for item in entropy if float(item.get("entropy") or 0) >= 7.0]
        _render_kv("entropy", suspicious or entropy[:60])
        _cache_agent_output(topic, _truncate(suspicious or entropy[:60]))
        return True

    if topic == "xrefs":
        xrefs = ACTIVE_SCAN.get("xrefs") or {}
        if not xrefs:
            return False
        lines = ["Cross-references:"]
        for item in (xrefs.get("strings") or [])[:30]:
            lines.append(f"\nString: {item.get('string')} @ {item.get('string_address')}")
            for ref in (item.get("xrefs_to_string") or [])[:8]:
                lines.append(f"  <- {ref.get('function') or '?'} at {ref.get('from')} ({ref.get('type')})")
        for item in (xrefs.get("imports") or [])[:30]:
            lines.append(f"\nImport: {item.get('import')} @ {item.get('address')}")
            for ref in (item.get("xrefs_to_import") or [])[:8]:
                lines.append(f"  <- {ref.get('function') or '?'} at {ref.get('from')} ({ref.get('type')})")
        _render_kv("xrefs", "\n".join(lines))
        _cache_agent_output(topic, "\n".join(lines))
        return True

    if topic == "callgraph":
        callgraph = ACTIVE_SCAN.get("callgraph") or {}
        if not callgraph:
            return False
        stats = callgraph.get("stats") or {}
        lines = [f"Call graph: nodes={stats.get('nodes', '?')} edges={stats.get('edges', '?')}"]
        for name, degree in (stats.get("hot_functions") or [])[:20]:
            node = callgraph.get(name) or {}
            lines.append(f"\n{name} (out={degree})")
            if node.get("calls"):
                lines.append("  calls: " + ", ".join(node["calls"][:12]))
            if node.get("called_by"):
                lines.append("  called_by: " + ", ".join(node["called_by"][:12]))
        _render_kv("callgraph", "\n".join(lines))
        _cache_agent_output(topic, "\n".join(lines))
        return True

    if topic == "analysis_graph":
        graph = ACTIVE_SCAN.get("analysis_graph") or {}
        if not graph:
            return False
        payload = {
            "stats": graph.get("stats"),
            "entry_candidates": graph.get("entry_candidates"),
            "sample_edges": (graph.get("edges") or [])[:30],
            "string_provenance": dict(list((graph.get("string_provenance") or {}).items())[:20]),
        }
        _render_kv("analysis-graph", payload)
        _cache_agent_output(topic, _truncate(payload))
        return True

    if topic == "function_scores":
        scores = ACTIVE_SCAN.get("function_scores") or {}
        top = scores.get("top") or []
        if not top:
            return False
        lines = ["Top suspicious functions:"]
        for idx, item in enumerate(top[:20], 1):
            lines.append(f"{idx:02d}. {item.get('function')} score={item.get('score')}")
            for reason in (item.get("reasons") or [])[:5]:
                lines.append(f"    - {reason}")
        _render_kv("function-scores", "\n".join(lines))
        _cache_agent_output(topic, "\n".join(lines))
        return True

    if topic == "execution_paths":
        paths = ACTIVE_SCAN.get("suspicious_paths") or []
        if not paths:
            return False
        lines = ["Ranked suspicious execution/API paths:"]
        for idx, item in enumerate(paths[:20], 1):
            lines.append(f"{idx:02d}. score={item.get('score')} sink={item.get('sink')}")
            lines.append("    " + " -> ".join(str(x) for x in item.get("path", [])))
        _render_kv("paths", "\n".join(lines))
        _cache_agent_output(topic, "\n".join(lines))
        return True

    if topic == "behavior_chains":
        chains = ACTIVE_SCAN.get("behavior_chains") or []
        if not chains:
            return False
        lines = ["Behavior chains:"]
        for idx, item in enumerate(chains[:20], 1):
            lines.append(f"{idx:02d}. {item.get('name')} confidence={item.get('confidence')}")
            lines.append(f"    Function: {item.get('function')} score={item.get('function_score')}")
            lines.append(f"    Sequence: {' -> '.join(item.get('sequence') or [])}")
            lines.append(f"    Assessment: {item.get('interpretation')}")
        _render_kv("behavior-chains", "\n".join(lines))
        _cache_agent_output(topic, "\n".join(lines))
        return True

    if topic == "capabilities":
        payload = {
            "behavior_scores": ACTIVE_SCAN.get("behavior_scores"),
            "capabilities": ACTIVE_SCAN.get("capabilities"),
            "yara_matches": ACTIVE_SCAN.get("yara_matches"),
            "function_clusters": ACTIVE_SCAN.get("function_clusters"),
        }
        if not any(payload.values()):
            return False
        _render_kv("capabilities", payload)
        _cache_agent_output(topic, _truncate(payload))
        return True

    if topic == "packed":
        packed = ACTIVE_SCAN.get("packed")
        if not packed:
            return False
        _render_kv("packed", packed)
        _cache_agent_output(topic, _truncate(packed))
        return True

    if topic == "evidence":
        findings = ACTIVE_SCAN.get("deduplicated_findings") or ACTIVE_SCAN.get("findings") or []
        if not findings:
            return False
        lines = ["Evidence-backed findings:"]
        for item in findings[:20]:
            lines.append(f"\n[{item.get('risk')}] {item.get('flag')} confidence={float(item.get('confidence') or 0):.2f}")
            lines.append(f"  source: {item.get('source')}")
            for ev in (item.get("evidence") or [])[:8]:
                lines.append(f"  - {ev}")
        _render_kv("evidence", "\n".join(lines))
        _cache_agent_output(topic, "\n".join(lines))
        return True

    if topic == "secrets":
        pipeline = ACTIVE_SCAN.get("pipeline") or {}
        secrets = ((pipeline.get("scan") or {}).get("secrets")) or {}
        if not secrets:
            return False
        _render_kv("secrets", secrets)
        _cache_agent_output(topic, _truncate(secrets))
        return True

    return False


def _agent_for_topic(topic: str):
    return {
        "suspicious_strings": strings_agent,
        "imports": symbols_agent,
        "protections": scanner_agent,
        "metadata": metadata_agent,
        "re_leads": re_agent,
        "functions": re_agent,
        "xrefs": re_agent,
        "callgraph": re_agent,
        "analysis_graph": re_agent,
        "function_scores": re_agent,
        "execution_paths": re_agent,
        "behavior_chains": re_agent,
        "secrets": secrets_agent,
        "sections": metadata_agent,
        "entropy": pe_scanner_agent if detect_format(ACTIVE_SCAN.get("path") or "") == "PE" else metadata_agent,
    }.get(topic)


def _prompt_for_topic(topic: str, path: str) -> str:
    prompts = {
        "suspicious_strings": f'List high-signal suspicious strings in "{path}". No filler.',
        "imports": f'List risky and review-only imports in "{path}". Compact.',
        "protections": f'List protection flags for "{path}". One line each.',
        "metadata": f'Return format, arch, entry point, size for "{path}".',
        "re_leads": f'List RE leads (functions, xrefs, imports) for "{path}".',
        "functions": f'List likely RE functions in "{path}".',
        "xrefs": f'List string xrefs and RE leads for "{path}".',
        "callgraph": f'List callgraph callers/callees for high-signal functions in "{path}". Use graph evidence.',
        "analysis_graph": f'Summarize the unified analysis graph for "{path}": nodes, edges, string provenance, and import usage.',
        "function_scores": f'Rank suspicious functions in "{path}" using graph scores and cite reasons.',
        "execution_paths": f'Trace ranked execution/API paths in "{path}" from entrypoints to suspicious functions/imports.',
        "behavior_chains": f'List behavior chains in "{path}" with function, sequence, interpretation, and confidence.',
        "secrets": f'List embedded secrets/tokens/passwords in "{path}".',
        "sections": f'List sections with flags and entropy for "{path}".',
        "entropy": f'List high-entropy or packed sections in "{path}".',
    }
    return prompts.get(topic, f'Analyze {topic} in "{path}". Compact.')


def dispatch_agent(agent, prompt, sessions):
    result = Runner.run_sync(agent, prompt, session=sessions, max_turns=10)
    return result.final_output if hasattr(result, "final_output") else str(result)


def _looks_like_handoff_placeholder(output: str) -> bool:
    lower = str(output).lower()
    return any(
        phrase in lower
        for phrase in (
            "transferred the request",
            "handed off",
            "handoff",
            "agent handled the request",
            "no further tool usage is needed",
        )
    )


def _handle_topic(topic: str, sessions: SQLiteSession, refresh: bool = False):
    path = _require_active()
    if not path:
        return

    agent = _agent_for_topic(topic)
    cached_output = (ACTIVE_SCAN.get("agent_outputs") or {}).get(topic)
    if agent and cached_output and not refresh:
        _set_last_topic(topic)
        chat_print(cached_output, prefix=topic)
        return

    if not agent:
        if not refresh and _render_cached_topic(topic):
            return
        if _render_cached_topic(topic):
            return
        chat_print(f"No cached data for topic: {topic}", C.YELLOW, "!")
        return

    if refresh:
        prompt = (
            f'Expand on "{topic}" for binary "{path}". '
            f'Show all raw entries, offsets, and evidence not in the initial scan. '
            f'Use tools only if cached data is insufficient. Be concise.'
        )
    else:
        prompt = _prompt_for_topic(topic, path)
    status = f"[bold cyan]Routing {topic} to {agent.name}...[/]"
    try:
        _set_last_topic(topic)
        status_ctx = console().status(status, spinner="dots") if RICH_AVAILABLE else nullcontext()
        with status_ctx:
            output = dispatch_agent(agent, prompt, sessions)
        _cache_agent_output(topic, str(output))
        chat_print(str(output), prefix=topic)
    except Exception as exc:
        chat_print(f"Error: {exc}", C.RED, "!")


def _handle_decompile(function_name: str, sessions: SQLiteSession):
    path = _require_active()
    if not path:
        return
    cached = (ACTIVE_SCAN.get("agent_outputs") or {}).get(f"decompile:{function_name}")
    if cached:
        _set_last_topic("decompile")
        chat_print(cached, prefix=f"decompile:{function_name}")
        return
    _set_last_topic("decompile")
    prompt = f'Decompile {function_name} in "{path}". Keep output focused and defensive.'
    try:
        status_ctx = console().status(f"[bold cyan]Decompiling {function_name}...[/]", spinner="dots") if RICH_AVAILABLE else nullcontext()
        with status_ctx:
            output = dispatch_agent(decompile_agent, prompt, sessions)
        _cache_agent_output(f"decompile:{function_name}", str(output))
        chat_print(str(output), prefix=f"decompile:{function_name}")
    except Exception as exc:
        chat_print(f"Error: {exc}", C.RED, "!")


def _handle_finding_detail(finding: dict, sessions: SQLiteSession, refresh: bool = True):
    path = _require_active()
    if not path:
        return

    ACTIVE_SCAN["last_finding"] = finding
    _set_last_topic("finding")

    flag = finding.get("flag", "finding")
    cache_key = f"finding:{flag}"
    cached = (ACTIVE_SCAN.get("agent_outputs") or {}).get(cache_key)
    if cached and not refresh:
        chat_print(cached, prefix=f"finding:{flag}")
        return

    agent = _agent_for_finding(finding)
    compact_finding = {
        "flag": finding.get("flag"),
        "risk": finding.get("risk"),
        "status": finding.get("status"),
        "why": finding.get("human"),
        "fix": finding.get("fix"),
    }
    prompt = (
        f'Drill into finding for "{path}". '
        f'Finding: {json.dumps(compact_finding, default=str)}. '
        f'Run the relevant tool if it can provide more evidence. '
        f'Return: extra evidence found, affected symbols/strings/flags, whether more detail was found, next defensive step. Concise.'
    )

    try:
        status_ctx = (
            console().status(f"[bold cyan]Drilling into {flag} with {agent.name}...[/]", spinner="dots")
            if RICH_AVAILABLE
            else nullcontext()
        )
        with status_ctx:
            output = dispatch_agent(agent, prompt, sessions)
        _cache_agent_output(cache_key, str(output))
        chat_print(str(output), prefix=f"finding:{flag}")
    except Exception as exc:
        chat_print(f"Error: {exc}", C.RED, "!")


def _handle_scan(path: str, sessions: SQLiteSession):
    resolved, found = resolve_path(path)
    if not found:
        chat_print(f"File not found: {path}", C.RED, "!")
        return
    prompt = f'Analyze this binary and cache the active target: "{resolved}"'
    try:
        status_ctx = console().status("[bold cyan]AnalyzerAgent scanning and caching active target...[/]", spinner="dots") if RICH_AVAILABLE else nullcontext()
        with status_ctx:
            output = dispatch_agent(analyzer_agent, prompt, sessions)
        _cache_agent_output("summary", str(output))
        pipeline = ACTIVE_SCAN.get("pipeline") or {}
        report = pipeline.get("report")
        if report:
            chat_print(report, prefix="scan")
        else:
            chat_print(str(output) or f"Active target set: {resolved}", prefix="scan")
    except Exception as exc:
        chat_print(f"Error: {exc}", C.RED, "!")


def run_chat():
    sessions = SQLiteSession(f"vuln_reporter_conversations_{int(time.time())}")
    show_welcome()
    print(f"  {C.CYAN}Ready. Drop a binary path and I will report weaknesses, fixes, and RE leads.{C.RESET}\n")

    while True:
        user_input = chat_input()
        if not user_input:
            continue
        if user_input.lower().strip() in ("quit", "exit", "q", "bye", "stop"):
            chat_print("Goodbye.", C.YELLOW)
            break

        command = _parse_command(user_input)

        if command["type"] == "help":
            _render_help()
            continue

        if command["type"] == "clear":
            _reset_active_scan()
            sessions = SQLiteSession(f"vuln_reporter_conversations_{int(time.time())}")
            chat_print("Session cleared. No active binary.", C.YELLOW, "session")
            continue

        if command["type"] == "active":
            _render_active()
            continue

        if command["type"] == "scan":
            _handle_scan(command["path"], sessions)
            continue

        if command["type"] == "topic":
            _handle_topic(command["topic"], sessions, refresh=command.get("refresh", False))
            continue

        if command["type"] == "finding":
            _handle_finding_detail(command["finding"], sessions, refresh=command.get("refresh", True))
            continue

        if command["type"] == "decompile":
            _handle_decompile(command["function"], sessions)
            continue

        try:
            path = ACTIVE_SCAN.get("path")
            routed_input = user_input
            if path:
                last = ACTIVE_SCAN.get("last_topic")
                routed_input = (
                    f'{user_input}\n'
                    f'Binary: "{path}" | Last topic: {last or "none"}\n'
                    f'Be brief. Use tools only if needed.'
                )
            if RICH_AVAILABLE:
                with console().status("[bold cyan]Routing ambiguous request...[/]", spinner="dots"):
                    output = dispatch_agent(orchestrator, routed_input, sessions)
            else:
                print(f"\n{C.BLUE}  [Orchestrator routing ...]{C.RESET}\n")
                output = dispatch_agent(orchestrator, routed_input, sessions)
            if _looks_like_handoff_placeholder(str(output)) and ACTIVE_SCAN.get("path"):
                fallback_topic = ACTIVE_SCAN.get("last_topic") or "re_leads"
                _handle_topic(fallback_topic, sessions, refresh=True)
                continue
            chat_print(str(output))
        except Exception as exc:
            chat_print(f"Error: {exc}", C.RED, "!")


if __name__ == "__main__":
    if "OPENAI_API_KEY" not in os.environ:
        print(f"\n{C.RED}{C.BOLD}  OPENAI_API_KEY not set.{C.RESET}")
        print(f"{C.RED}  PowerShell: $env:OPENAI_API_KEY = \"sk-proj-...\"{C.RESET}\n")
        sys.exit(1)
    run_chat()
