"""Report building and risk scoring for static binary analysis."""

import os
import textwrap

from tools.paths import detect_format
from tools.pe_analysis import pe_scan
from tools.static_analysis import (
    analyze_reverse_engineering,
    deduplicate_findings,
    extract_symbols,
    find_strings,
    prioritize_findings,
    run_checksec,
    run_deterministic_engines,
    scan_embedded_secrets,
)
from tools.ui import elapsed_ms, render_report, start_timer

LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
RISK_WEIGHT = {LOW: 1, MEDIUM: 2, HIGH: 3}


def _confidence_for(risk: str, evidence: list[str], source: str, strong: bool = False) -> float:
    base = {LOW: 0.45, MEDIUM: 0.58, HIGH: 0.68}.get(risk, 0.45)
    base += min(0.18, 0.04 * len(evidence or []))
    if strong:
        base += 0.12
    if source not in {"heuristic", "strings"}:
        base += 0.08
    return round(max(0.0, min(1.0, base)), 2)


def finding(flag: str, status: str, risk: str, human: str, fix: str, evidence: list[str] | None = None, source: str = "static", strong: bool = False) -> dict:
    evidence = evidence or ([status] if status else [])
    return {
        "flag": flag,
        "title": flag,
        "status": status,
        "risk": risk,
        "severity": risk,
        "human": human,
        "fix": fix,
        "confidence": _confidence_for(risk, evidence, source, strong=strong),
        "evidence": evidence[:20],
        "source": source,
    }


def _secret_findings_with_context(scan: dict) -> dict:
    raw = (scan.get("secrets") or {}).get("findings") or {}
    if not raw:
        return {}
    high_signal = {}
    xref_by_value = (scan.get("xrefs") or {}).get("by_value") or {}
    has_networking = bool(((scan.get("behavior_scores") or {}).get("clusters") or {}).get("networking"))
    for category, values in raw.items():
        clean_values = []
        for value in values:
            refs = xref_by_value.get(value) or []
            lower = str(value).lower()
            if category == "network":
                if refs or has_networking:
                    clean_values.append(value)
                continue
            if category in {"flags", "private_keys", "api_keys"} or refs or any(k in lower for k in ("password", "passwd", "token", "secret", "license", "serial")):
                clean_values.append(value)
        if clean_values:
            high_signal[category] = clean_values
    return high_signal


def build_findings(scan: dict) -> tuple[list[dict], str, int, int]:
    protections = scan.get("protections", {})
    symbols = scan.get("symbols", {})
    findings = []

    nx = protections.get("nx", "unknown").lower()
    if nx == "disabled":
        findings.append(
            finding(
                "No DEP / NX",
                "disabled",
                HIGH,
                "The program's stack and heap may allow executable data. If a memory corruption bug exists, injected data can become code.",
                "Re-link with NX/DEP enabled. MSVC: /NXCOMPAT. GCC/Clang: remove -z execstack and keep .note.GNU-stack non-executable.",
            )
        )
    elif nx == "enabled":
        findings.append(
            finding(
                "DEP / NX",
                "enabled",
                LOW,
                "Injected data on the stack or heap cannot be executed directly.",
                "No action needed; keep this protection enabled.",
            )
        )

    pie = protections.get("pie", "unknown").lower()
    if "disabled" in pie or pie == "no pie":
        findings.append(
            finding(
                "No ASLR / PIE",
                "disabled",
                HIGH,
                "The program loads at predictable addresses, which makes code-reuse attacks much easier if another bug is present.",
                "Build a position-independent executable. MSVC: /DYNAMICBASE. GCC/Clang: -fPIE -pie.",
            )
        )
    elif "enabled" in pie:
        findings.append(
            finding(
                "ASLR / PIE",
                "enabled",
                LOW,
                "The image base is randomized at load time, so attackers need an address leak before targeting code inside the binary.",
                "No action needed.",
            )
        )

    canary = protections.get("canary", "unknown").lower()
    if canary in ("disabled", "no canary found"):
        findings.append(
            finding(
                "No Stack Canary",
                "disabled",
                HIGH,
                "There is no stack-cookie protection. A stack overflow can overwrite a saved return address without a compiler-inserted guard catching it.",
                "Recompile with stack canaries. MSVC: /GS. GCC/Clang: -fstack-protector-strong or -fstack-protector-all.",
            )
        )
    elif canary == "enabled":
        findings.append(
            finding(
                "Stack Canary",
                "enabled",
                LOW,
                "Compiler-inserted cookies guard saved return addresses from simple linear stack overflows.",
                "No action needed.",
            )
        )

    relro = protections.get("relro", "N/A").lower()
    if relro not in ("n/a", ""):
        if relro in ("disabled", "no relro"):
            findings.append(
                finding(
                    "No RELRO",
                    "disabled",
                    HIGH,
                    "The Global Offset Table is writable at runtime, so a write primitive could redirect library calls.",
                    "Link with full RELRO: -Wl,-z,relro,-z,now.",
                )
            )
        elif relro == "partial":
            findings.append(
                finding(
                    "Partial RELRO",
                    "partial",
                    MEDIUM,
                    "Some GOT entries can remain writable because library calls may be resolved lazily.",
                    "Switch to full RELRO: -Wl,-z,relro,-z,now.",
                )
            )
        elif relro == "full":
            findings.append(
                finding(
                    "Full RELRO",
                    "full",
                    LOW,
                    "The GOT is read-only after load, blocking GOT-overwrite techniques.",
                    "No action needed.",
                )
            )

    dangerous = symbols.get("dangerous_functions", [])
    contextual_api_findings = [
        item for item in scan.get("engine_findings") or []
        if item.get("source") == "analysis_graph" and " uses " in str(item.get("flag"))
    ]
    if dangerous and not contextual_api_findings:
        names = ", ".join(dangerous)
        xref_names = (scan.get("xrefs") or {}).get("by_value") or {}
        evidence = [f"import={name}" + (f" callers={len(xref_names.get(name) or [])}" if xref_names.get(name) else "") for name in dangerous]
        findings.append(
            finding(
                "Dangerous C-runtime calls",
                names,
                HIGH,
                f"The binary imports high-risk routines ({names}) that commonly skip bounds checks or parse untrusted format strings.",
                "Replace with safer patterns: gets -> fgets, strcpy/strcat -> bounded copies or std::string, sprintf -> snprintf, scanf -> width-limited formats.",
                evidence,
                "imports",
                True,
            )
        )

    review = symbols.get("review_functions", [])
    if review and not contextual_api_findings:
        names = ", ".join(review)
        findings.append(
            finding(
                "Memory/input routines need review",
                names,
                MEDIUM,
                f"The binary imports routines ({names}) that are safe only when their size and format arguments are correct.",
                "Review the call sites in disassembly/decompiler output and verify buffer sizes, length checks, and format strings.",
                [f"review_import={name}" for name in review],
                "imports",
            )
        )

    interesting = scan.get("strings", {}).get("interesting") or {}
    string_xrefs = (scan.get("xrefs") or {}).get("strings") or []
    if interesting and (string_xrefs or scan.get("format") != "PE"):
        hints = list(interesting.keys())
        sample = []
        for values in interesting.values():
            if isinstance(values, list) and values:
                sample.append(str(values[0])[:120])
            if len(sample) >= 3:
                break
        sample_text = " / ".join(sample)
        findings.append(
            finding(
                "Suspicious embedded strings",
                ", ".join(hints[:5]),
                MEDIUM,
                "The binary contains strings that look relevant to secrets, licensing, paths, URLs, or challenge logic"
                + (f' (for example "{sample_text}")' if sample_text else "")
                + ". These are review leads, and confidence is highest when xrefs show runtime use.",
                "Audit referenced strings first. Move real secrets out of the binary, strip release debug strings, and avoid client-side-only license checks.",
                [f"pattern={hint}" for hint in hints[:8]] + [f"xrefed_strings={len(string_xrefs)}"],
                "strings",
                bool(string_xrefs),
            )
        )

    secrets = _secret_findings_with_context(scan)
    if secrets:
        cats = ", ".join(secrets.keys())
        first_cat = next(iter(secrets))
        first_val = secrets[first_cat][0] if secrets[first_cat] else ""
        sample = f' Example: "{str(first_val)[:80]}".' if first_val else ""
        findings.append(
            finding(
                "Hardcoded secrets / license data",
                cats,
                HIGH,
                f"Embedded secrets were found in the binary ({cats}).{sample} Because they ship inside the file, anyone can extract and reuse them.",
                "Do not ship secrets inside the binary. Validate licenses server-side or with signed tokens; load API keys from user-controlled config or environment.",
                [f"{cat}: {str(value)[:120]}" for cat, values in secrets.items() for value in values[:3]],
                "secrets",
                True,
            )
        )

    if scan.get("format") == "PE":
        cfg = protections.get("cfg", "unknown").lower()
        seh = protections.get("seh", "unknown").lower()
        if cfg == "disabled":
            findings.append(
                finding(
                    "No Control Flow Guard",
                    "disabled",
                    HIGH,
                    "Windows CFG is off, so corrupted indirect calls or vtables are not validated at runtime.",
                    "Enable CFG in the linker with /GUARD:CF and ensure linked libraries are CFG-aware.",
                )
            )
        elif cfg == "enabled":
            findings.append(
                finding(
                    "Control Flow Guard",
                    "enabled",
                    LOW,
                    "CFG validates indirect calls at runtime, reducing common code-reuse redirection paths.",
                    "No action needed.",
                )
            )
        if seh == "enabled":
            findings.append(
                finding(
                    "SEH records present",
                    "present",
                    MEDIUM,
                    "Structured exception handling is present. On older 32-bit builds, stack-based SEH records can become an overwrite target.",
                    "Prefer modern x64 builds and keep SafeSEH/SEHOP enabled where applicable.",
                )
            )

    re_summary = scan.get("reverse_engineering") or {}
    priority_functions = re_summary.get("priority_functions") or []
    behavioral_imports = symbols.get("behavioral_imports") or re_summary.get("behavioral_imports") or {}
    if priority_functions or behavioral_imports:
        names = [f.get("name") or f.get("function") or "?" for f in priority_functions[:5]]
        import_names = list(behavioral_imports.keys())[:5] if isinstance(behavioral_imports, dict) else []
        status = ", ".join(names + import_names)
        lead_text = f" Leads include: {status}." if status else ""
        findings.append(
            finding(
                "Reverse-engineering leads",
                status or "review suggested",
                MEDIUM,
                "The static scan found functions, imports, or strings that are likely to explain validation, secret handling, dynamic loading, anti-debugging, or network behavior."
                + lead_text,
                "Start RE from these leads: inspect their decompiler output, cross-references to suspicious strings, and callers before doing broad manual analysis.",
                [f"function={name}" for name in names[:5]] + [f"import={name}" for name in import_names[:5]],
                "radare2",
                bool((scan.get("xrefs") or {}).get("strings") or (scan.get("xrefs") or {}).get("imports")),
            )
        )

    findings.extend(scan.get("engine_findings") or [])
    findings = deduplicate_findings(findings)
    findings, additional = prioritize_findings(findings)
    scan["additional_observations"] = additional
    scan["deduplicated_findings"] = findings
    scan["confidence_scores"] = {
        item.get("flag") or item.get("title"): item.get("confidence", 0.0)
        for item in findings
    }

    high_count = sum(1 for item in findings if item["risk"] == HIGH)
    med_count = sum(1 for item in findings if item["risk"] == MEDIUM)
    if high_count >= 3 or (high_count >= 1 and med_count >= 2):
        overall = HIGH
    elif high_count >= 1 or med_count >= 1:
        overall = MEDIUM
    else:
        overall = LOW
    return findings, overall, high_count, med_count


def top_priority_fix(findings: list[dict]) -> str:
    if not findings:
        return "No high-priority hardening action; the program follows the checked defensive defaults."
    priority_order = [
        "Hardcoded secrets / license data",
        "No Stack Canary",
        "Dangerous C-runtime calls",
        "No DEP / NX",
        "No ASLR / PIE",
        "No Control Flow Guard",
        "No RELRO",
        "Partial RELRO",
        "Reverse-engineering leads",
        "SEH records present",
        "Suspicious embedded strings",
    ]
    by_flag = {item["flag"]: item for item in findings}
    for flag in priority_order:
        item = by_flag.get(flag)
        if item and item["risk"] in (HIGH, MEDIUM):
            return item["fix"]
    for risk in (HIGH, MEDIUM):
        matching = [item for item in findings if item["risk"] == risk]
        if matching:
            return matching[0]["fix"]
    return "No high-priority hardening action; keep the current protections enabled."


def format_report(binary_path: str, scan: dict, findings: list[dict], overall: str, high_count: int, med_count: int, top_fix: str) -> str:
    arch = scan.get("architecture", {})
    fmt = scan.get("format", "unknown")
    name = os.path.basename(binary_path)
    low_count = len(findings) - high_count - med_count
    lines = [
        "=" * 64,
        f"  Security Report - {name}",
        "=" * 64,
        f"  Format / Arch : {fmt} {arch.get('arch', '?')}-{arch.get('bits', '?')}",
        f"  Overall Risk  : {overall}  ({high_count} high, {med_count} medium, {low_count} low)",
        "",
        "  Findings",
    ]
    if not findings:
        lines.append("    (no findings; the program follows the checked defensive defaults)")
    else:
        order = {HIGH: 0, MEDIUM: 1, LOW: 2}
        for item in sorted(findings, key=lambda x: order.get(x["risk"], 3)):
            lines.append("")
            lines.append(f"    [{item['risk']}] {item['flag']}")
            human_lines = textwrap.wrap(item["human"], width=72) or [""]
            lines.append(f"      What : {human_lines[0]}")
            for extra in human_lines[1:]:
                lines.append(f"             {extra}")
            fix_lines = textwrap.wrap(item["fix"], width=72) or [""]
            lines.append(f"      Fix  : {fix_lines[0]}")
            for extra in fix_lines[1:]:
                lines.append(f"             {extra}")
    lines.append("")
    lines.append(f"  Top priority fix: {top_fix}")
    lines.append("=" * 64)
    return "\n".join(lines)


def run_full_pipeline(binary_path: str) -> dict:
    timer = start_timer()
    fmt = detect_format(binary_path)
    if fmt == "PE":
        scan = pe_scan(binary_path)
        if "error" in scan:
            return scan
    else:
        protections = run_checksec(binary_path)
        symbols = extract_symbols(binary_path)
        strings = find_strings(binary_path)
        scan = {
            "binary": binary_path,
            "format": "ELF" if fmt == "ELF" else fmt,
            "protections": {
                "nx": protections.get("nx", "unknown"),
                "pie": protections.get("pie", "unknown"),
                "canary": protections.get("canary", "unknown"),
                "relro": protections.get("relro", "unknown"),
                "aslr": protections.get("aslr", "unknown"),
            },
            "architecture": {
                "arch": symbols.get("arch", protections.get("arch", "?")),
                "bits": symbols.get("bits", protections.get("bits", "?")),
                "entry_point": symbols.get("entry_point", "?"),
            },
            "symbols": {
                "dangerous_functions": symbols.get("dangerous_functions", []),
                "review_functions": symbols.get("review_functions", []),
                "behavioral_imports": symbols.get("behavioral_imports", {}),
                "win_functions": symbols.get("win_functions", {}),
                "has_win": symbols.get("has_win", False),
                "plt_imports": symbols.get("plt_imports", []),
            },
            "strings": {"total": strings.get("total_strings", 0), "interesting": strings.get("interesting", {})},
        }

    scan["file_size"] = os.path.getsize(binary_path) if os.path.exists(binary_path) else None

    try:
        scan["secrets"] = scan_embedded_secrets(binary_path)
    except Exception as exc:
        scan["secrets"] = {"error": str(exc)}

    try:
        scan = run_deterministic_engines(binary_path, scan)
    except Exception as exc:
        scan["engine_error"] = str(exc)
        scan.setdefault("xrefs", {"strings": [], "imports": [], "functions": [], "by_value": {}})
        scan.setdefault("callgraph", {"stats": {"nodes": 0, "edges": 0, "error": str(exc)}, "edges": []})
        scan.setdefault("capabilities", {"capa": {"error": str(exc)}, "import_score": {}, "groups": {}})
        scan.setdefault("packed", {"is_packed": False, "packed": False, "confidence": 0.0, "evidence": [str(exc)]})
        scan.setdefault("yara_matches", {"matches": []})
        scan.setdefault("behavior_scores", {"score": 0, "hits": {}, "clusters": {}, "details": {}})
        scan.setdefault("function_clusters", {})
        scan.setdefault("analysis_graph", {"nodes": {}, "edges": [], "adjacency": {}, "reverse_adjacency": {}, "stats": {}})
        scan.setdefault("function_scores", {"scores": {}, "top": []})
        scan.setdefault("suspicious_paths", [])
        scan.setdefault("behavior_chains", [])
        scan.setdefault("additional_observations", [])

    try:
        scan["reverse_engineering"] = analyze_reverse_engineering(binary_path, scan)
    except Exception as exc:
        scan["reverse_engineering"] = {"error": str(exc)}

    findings, overall, high_count, med_count = build_findings(scan)
    top_fix = top_priority_fix(findings)
    elapsed = elapsed_ms(timer)
    report = render_report(binary_path, scan, findings, overall, high_count, med_count, top_fix, elapsed)
    return {
        "overall_risk": overall,
        "top_priority_fix": top_fix,
        "report": report,
        "scan_time_ms": elapsed,
        "scan": scan,
        "findings": findings,
    }
