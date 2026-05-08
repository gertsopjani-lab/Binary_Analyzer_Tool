"""Terminal UI rendering helpers for scanner output."""

from __future__ import annotations

import os
import shutil
import time
from io import StringIO
from typing import Iterable

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - fallback path for minimal installs
    RICH_AVAILABLE = False


SEVERITY_STYLES = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold bright_red",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
    "SAFE": "bold green",
    "ENABLED": "bold green",
    "DISABLED": "bold bright_red",
    "UNKNOWN": "dim white",
}


def console() -> "Console":
    return Console(highlight=False, soft_wrap=False)


def _term_width(default: int = 112) -> int:
    return max(88, min(shutil.get_terminal_size((default, 30)).columns, 132))


def severity_style(severity: str) -> str:
    return SEVERITY_STYLES.get((severity or "UNKNOWN").upper(), "white")


def severity_badge(severity: str) -> "Text":
    value = (severity or "UNKNOWN").upper()
    return Text(f" {value} ", style=severity_style(value))


def _risk_count(findings: list[dict], risk: str) -> int:
    return sum(1 for item in findings if (item.get("risk") or "").upper() == risk)


def _risk_tab_text(label: str, count: int, active: bool = False) -> "Text":
    style = severity_style(label) if count else "dim"
    if active and count:
        style = style + " reverse"
    return Text(f" {label} {count} ", style=style)


def _compact_evidence(item: dict, limit: int = 2) -> str:
    evidence = [str(e) for e in (item.get("evidence") or []) if str(e).strip()]
    if evidence:
        return "\n".join(f"- {value[:150]}" for value in evidence[:limit])
    return _finding_evidence(item)


def _assessment_text(item: dict) -> str:
    human = str(item.get("human") or "")
    return human[:260]


def protection_badge(value: str) -> "Text":
    normalized = (value or "unknown").lower()
    if normalized in {"enabled", "full"}:
        return Text(f" {value} ", style="bold green")
    if normalized in {"disabled", "no relro", "no pie", "no canary found"}:
        return Text(f" {value} ", style="bold bright_red")
    if normalized in {"partial", "present"}:
        return Text(f" {value} ", style="bold yellow")
    if normalized in {"n/a", ""}:
        return Text(" n/a ", style="dim")
    return Text(f" {value} ", style="dim white")


def format_bytes(size: int | None) -> str:
    if size is None:
        return "unknown"
    value = float(size)
    for suffix in ("B", "KB", "MB", "GB"):
        if value < 1024 or suffix == "GB":
            return f"{value:.1f} {suffix}" if suffix != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def start_timer() -> float:
    return time.perf_counter()


def elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000


def _finding_evidence(item: dict) -> str:
    status = str(item.get("status") or "").strip()
    if status and status.lower() not in {"enabled", "disabled", "partial", "present"}:
        return status
    return status or "static analysis finding"


def _affected_component(item: dict) -> str:
    flag = item.get("flag", "")
    lower = flag.lower()
    if "canary" in lower or "dep" in lower or "aslr" in lower or "pie" in lower or "relro" in lower or "cfg" in lower:
        return "Binary hardening"
    if "runtime" in lower or "memory/input" in lower:
        return "Imports / call sites"
    if "secret" in lower or "string" in lower:
        return "Embedded data"
    if "reverse" in lower:
        return "RE triage"
    if "seh" in lower:
        return "Windows exception handling"
    return "Static analysis"


def _fix_priority(item: dict) -> str:
    risk = item.get("risk", "LOW")
    flag = item.get("flag", "")
    if risk == "HIGH":
        return "P0" if "secret" in flag.lower() else "P1"
    if risk == "MEDIUM":
        return "P2"
    return "P3"


def _estimated_impact(item: dict) -> str:
    risk = item.get("risk", "LOW")
    flag = item.get("flag", "").lower()
    if "secret" in flag:
        return "High: removes extractable credentials"
    if "canary" in flag or "dep" in flag or "aslr" in flag or "cfg" in flag:
        return "High: raises exploitation cost"
    if risk == "MEDIUM":
        return "Medium: reduces review surface"
    return "Low: keep current control"


def _plain_report(binary_path: str, scan: dict, findings: list[dict], overall: str, high_count: int, med_count: int, top_fix: str, elapsed: float | None) -> str:
    arch = scan.get("architecture", {})
    low_count = len(findings) - high_count - med_count
    lines = [
        "=" * 72,
        f"Binary Vulnerability Reporter :: {os.path.basename(binary_path)}",
        "=" * 72,
        f"Target: {binary_path}",
        f"Format: {scan.get('format', 'unknown')} {arch.get('arch', '?')}-{arch.get('bits', '?')}",
        f"Risk: {overall} | High: {high_count} Medium: {med_count} Low: {low_count}",
    ]
    if elapsed is not None:
        lines.append(f"Scan time: {elapsed:.0f} ms")
    lines.extend(["", "Vulnerabilities Found"])
    for item in findings:
        lines.extend(
            [
                f"- [{item.get('risk')}] {item.get('flag')} ({_affected_component(item)})",
                f"  Why: {item.get('human')}",
                f"  Confidence: {float(item.get('confidence') or 0):.2f}",
                f"  Evidence: {_finding_evidence(item)}",
                f"  Fix: {item.get('fix')}",
            ]
        )
    lines.extend(["", f"Top Priority Fix: {top_fix}", "=" * 72])
    return "\n".join(lines)


def _render_header(binary_path: str, scan: dict, overall: str, elapsed: float | None):
    arch = scan.get("architecture", {})
    target = os.path.basename(binary_path)
    title = Text()
    title.append("BINARY VULNERABILITY REPORTER", style="bold bright_cyan")
    title.append("  //  ", style="dim")
    title.append("STATIC RE TRIAGE", style="bold magenta")

    subtitle = Text()
    subtitle.append("target ", style="dim")
    subtitle.append(target, style="bold white")
    subtitle.append("  format ", style="dim")
    subtitle.append(str(scan.get("format", "unknown")), style="bold cyan")
    subtitle.append("  arch ", style="dim")
    subtitle.append(f"{arch.get('arch', '?')}-{arch.get('bits', '?')}", style="bold cyan")
    subtitle.append("  risk ", style="dim")
    subtitle.append(overall, style=severity_style(overall))
    if elapsed is not None:
        subtitle.append("  time ", style="dim")
        subtitle.append(f"{elapsed:.0f} ms", style="bold green")

    return Panel(
        Align.center(Group(title, subtitle), vertical="middle"),
        border_style="bright_cyan",
        box=box.DOUBLE,
        padding=(1, 2),
    )


def _summary_panel(binary_path: str, scan: dict, findings: list[dict], overall: str, high_count: int, med_count: int):
    low_count = len(findings) - high_count - med_count
    secrets = (scan.get("secrets") or {}).get("findings") or {}
    re_leads = scan.get("reverse_engineering") or {}
    priority_functions = re_leads.get("priority_functions") or []
    packed = scan.get("packed") or {}
    behavior = scan.get("behavior_scores") or {}

    grid = Table.grid(expand=True)
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(
        Panel(Group(Text("Risk Score", style="dim"), severity_badge(overall)), border_style=severity_style(overall), box=box.ROUNDED),
        Panel(
            Group(
                Text("Findings", style="dim"),
                Text(f"{high_count} high  {med_count} medium  {low_count} low", style="bold white"),
            ),
            border_style="bright_black",
            box=box.ROUNDED,
        ),
        Panel(
            Group(
                Text("Evidence", style="dim"),
                Text(
                    f"{len(secrets)} secret sets  {len(priority_functions)} RE leads  {behavior.get('score', 0)} behavior",
                    style="bold white",
                ),
            ),
            border_style="bright_black",
            box=box.ROUNDED,
        ),
    )

    target_info = Table.grid(expand=True)
    target_info.add_column(style="dim", width=14)
    target_info.add_column(style="white")
    target_info.add_row("Path", binary_path)
    target_info.add_row("Size", format_bytes(scan.get("secrets", {}).get("file_size") or scan.get("file_size")))
    target_info.add_row("Entry", str((scan.get("architecture") or {}).get("entry_point", "?")))
    target_info.add_row("Packed", f"{bool(packed.get('is_packed') or packed.get('packed'))} ({float(packed.get('confidence') or 0):.2f})")

    return Group(
        Panel(target_info, title="[bold cyan]Target[/]", border_style="cyan", box=box.ROUNDED),
        grid,
    )


def _vulnerability_table(findings: list[dict]):
    table = Table(
        title="Vulnerabilities Found",
        title_style="bold bright_red",
        box=box.SIMPLE_HEAVY,
        border_style="bright_black",
        expand=True,
        show_lines=True,
    )
    table.add_column("Severity", width=12, no_wrap=True)
    table.add_column("Conf", width=7, justify="right")
    table.add_column("Vulnerability", min_width=22, style="bold white")
    table.add_column("Why It Matters", ratio=2)
    table.add_column("Evidence", ratio=1)
    table.add_column("Affected Component", width=22)

    ordered = sorted(findings, key=lambda item: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(item.get("risk"), 3))
    for item in ordered:
        table.add_row(
            severity_badge(item.get("risk", "UNKNOWN")),
            f"{float(item.get('confidence') or 0):.2f}",
            str(item.get("flag", "?")),
            str(item.get("human", "")),
            "; ".join(str(e) for e in (item.get("evidence") or [])[:3]) or _finding_evidence(item),
            _affected_component(item),
        )
    return Panel(table, border_style="bright_red", box=box.ROUNDED)


def _risk_tabs(findings: list[dict]):
    """Render findings grouped as terminal tabs: High, Medium, Low."""
    counts = {risk: _risk_count(findings, risk) for risk in ("HIGH", "MEDIUM", "LOW")}
    active = "HIGH" if counts["HIGH"] else "MEDIUM" if counts["MEDIUM"] else "LOW"

    tabs = Table.grid(expand=False)
    tabs.add_column()
    tabs.add_column()
    tabs.add_column()
    tabs.add_row(
        _risk_tab_text("HIGH", counts["HIGH"], active == "HIGH"),
        _risk_tab_text("MEDIUM", counts["MEDIUM"], active == "MEDIUM"),
        _risk_tab_text("LOW", counts["LOW"], active == "LOW"),
    )

    groups = []
    for risk in ("HIGH", "MEDIUM", "LOW"):
        items = [item for item in findings if (item.get("risk") or "").upper() == risk]
        if not items:
            continue

        table = Table(
            box=box.SIMPLE,
            border_style="bright_black",
            expand=True,
            show_header=True,
            header_style=severity_style(risk),
            pad_edge=False,
        )
        table.add_column("Finding", min_width=22, style="bold white")
        table.add_column("Conf", width=6, justify="right")
        table.add_column("Evidence", ratio=2)
        table.add_column("Assessment", ratio=2)

        for item in sorted(items, key=lambda row: float(row.get("confidence") or 0), reverse=True):
            table.add_row(
                str(item.get("flag", "?")),
                f"{float(item.get('confidence') or 0):.2f}",
                _compact_evidence(item),
                _assessment_text(item),
            )

        groups.append(
            Panel(
                table,
                title=f"[{severity_style(risk)}]{risk} risk[/]",
                border_style=severity_style(risk),
                box=box.ROUNDED,
                padding=(0, 1),
            )
        )

    if not groups:
        groups.append(Panel("No findings in the current scan.", border_style="green", box=box.ROUNDED))

    return Group(
        Panel(Align.center(tabs), title="[bold cyan]Risk tabs[/]", border_style="bright_black", box=box.ROUNDED),
        *groups,
    )


def _next_steps_panel(findings: list[dict], top_fix: str):
    high = [item for item in findings if item.get("risk") == "HIGH"]
    chains = [item for item in findings if item.get("source") == "behavior_chain"]
    lines = []
    if chains:
        lines.append("1. Decompile the top behavior-chain function and verify reachability from the ranked path.")
    if high:
        lines.append("2. Validate the highest-confidence HIGH finding at the exact function/API call site.")
    lines.append(f"3. Remediation focus: {top_fix}")
    return Panel("\n".join(lines), title="[bold green]Next steps[/]", border_style="green", box=box.ROUNDED)


def _additional_observations_panel(scan: dict):
    items = scan.get("additional_observations") or []
    if not items:
        return None
    lines = [f"- [{item.get('risk')}] {item.get('flag')} confidence={float(item.get('confidence') or 0):.2f}" for item in items[:20]]
    return Panel("\n".join(lines), title="[bold yellow]Additional observations[/]", border_style="yellow", box=box.ROUNDED)


def _re_tree(scan: dict):
    re_summary = scan.get("reverse_engineering") or {}
    symbols = scan.get("symbols") or {}
    tree = Tree("[bold magenta]Reverse Engineering Leads[/]")

    funcs = re_summary.get("priority_functions") or []
    func_branch = tree.add("[bold cyan]Priority functions[/]")
    if funcs:
        for func in funcs[:10]:
            name = func.get("name") or func.get("function") or "?"
            node = func_branch.add(f"{name} [dim]score={func.get('score', '?')} offset={func.get('offset') or func.get('address', '')}[/]")
            for reason in (func.get("reasons") or [])[:4]:
                node.add(f"[dim]{reason}[/]")
    else:
        func_branch.add("[dim]No strongly named validation/secret functions found[/]")

    imports = symbols.get("behavioral_imports") or re_summary.get("behavioral_imports") or {}
    import_branch = tree.add("[bold cyan]Behavioral imports[/]")
    if imports:
        iterable: Iterable = imports.items() if isinstance(imports, dict) else []
        for name, reason in list(iterable)[:12]:
            if isinstance(reason, dict):
                reason = reason.get("reason", "review behavior")
            import_branch.add(f"{name} [dim]- {reason}[/]")
    else:
        import_branch.add("[dim]No behavioral imports detected[/]")

    strings = re_summary.get("suspicious_strings") or []
    string_branch = tree.add("[bold cyan]Suspicious strings[/]")
    if strings:
        for item in strings[:8]:
            string_branch.add(f"{item.get('string', '')} [dim]{item.get('address') or ''}[/]")
    else:
        string_branch.add("[dim]No suspicious strings in RE summary[/]")

    xrefs = re_summary.get("string_xrefs") or []
    xref_branch = tree.add("[bold cyan]String xrefs[/]")
    if xrefs:
        for item in xrefs[:8]:
            xref_branch.add(f"{item.get('string', '')} -> {item.get('function') or item.get('from') or '?'}")
    else:
        xref_branch.add("[dim]No string xrefs available[/]")

    notes = re_summary.get("notes") or []
    if notes:
        note_branch = tree.add("[bold yellow]Limitations[/]")
        for note in notes:
            note_branch.add(f"[dim]{note}[/]")

    paths = re_summary.get("suspicious_paths") or []
    if paths:
        path_branch = tree.add("[bold cyan]Suspicious paths[/]")
        for item in paths[:6]:
            path_branch.add(f"{' -> '.join(str(x) for x in item.get('path', [])[:8])} [dim]score={item.get('score')}[/]")

    chains = re_summary.get("behavior_chains") or []
    if chains:
        chain_branch = tree.add("[bold cyan]Behavior chains[/]")
        for item in chains[:6]:
            chain_branch.add(
                f"{item.get('function')} [dim]{' -> '.join(item.get('sequence') or [])} confidence={item.get('confidence')}[/]"
            )

    return Panel(tree, border_style="magenta", box=box.ROUNDED)


def render_xref_tree(xrefs: dict) -> "Panel":
    """Render a provenance-oriented xref tree.

    Expected shape:
      {
        "strings": [ { "string": "...", "string_address": "0x...", "xrefs_to_string": [...], "call_path": [...] }, ... ],
        "imports": [ ... ],
      }
    """
    tree = Tree("[bold magenta]Xref Provenance[/]")
    strings = (xrefs or {}).get("strings") or []
    imports = (xrefs or {}).get("imports") or []
    if not strings and not imports:
        return None
    s_branch = tree.add("[bold cyan]String provenance[/]")
    if strings:
        for item in strings[:10]:
            label = f"{item.get('string','')[:120]} [dim]{item.get('string_address','')}[/]"
            node = s_branch.add(label)
            for ref in (item.get("xrefs_to_string") or [])[:8]:
                node.add(f"[dim]{ref.get('function') or '?'}[/]  from={ref.get('from')} type={ref.get('type')}")
            call_path = item.get("call_path") or []
            if call_path:
                node.add("[bold yellow]call path[/]: " + " -> ".join(str(x) for x in call_path[:10]))
    else:
        s_branch.add("[dim]No string provenance captured yet[/]")

    i_branch = tree.add("[bold cyan]Import xrefs[/]")
    if imports:
        for item in imports[:12]:
            i_branch.add(f"{item}")
    else:
        i_branch.add("[dim]No import xrefs captured yet[/]")

    return Panel(tree, border_style="magenta", box=box.ROUNDED)


def render_callgraph_summary(callgraph: dict) -> "Panel":
    """Render a compact callgraph summary and hot functions list."""
    tree = Tree("[bold magenta]Call Graph Summary[/]")
    stats = (callgraph or {}).get("stats") or {}
    if not stats or not stats.get("edges"):
        return None
    tree.add(f"[bold cyan]nodes[/]: {stats.get('nodes','?')}   [bold cyan]edges[/]: {stats.get('edges','?')}")
    hot = stats.get("hot_functions") or []
    hot_branch = tree.add("[bold cyan]hot functions (out-degree)[/]")
    if hot:
        for name, deg in hot[:12]:
            hot_branch.add(f"{name} [dim]out={deg}[/]")
    else:
        hot_branch.add("[dim]No callgraph data available[/]")
    return Panel(tree, border_style="magenta", box=box.ROUNDED)


def render_capability_summary(capabilities: dict) -> "Panel":
    """Render capability results from capa/import clustering."""
    tree = Tree("[bold magenta]Capabilities[/]")
    clusters = (capabilities or {}).get("clusters") or {}
    if not clusters and not ((capabilities or {}).get("capa") or {}).get("capabilities") and not ((capabilities or {}).get("import_score") or {}).get("hits"):
        return None
    if clusters:
        branch = tree.add("[bold cyan]inferred clusters[/]")
        for name, evidence in list(clusters.items())[:8]:
            branch.add(f"{name} [dim]{len(evidence) if isinstance(evidence, list) else 1} evidence item(s)[/]")
    capa = (capabilities or {}).get("capa") or {}
    if capa.get("capabilities"):
        branch = tree.add("[bold cyan]capa rules[/]")
        for item in capa.get("capabilities", [])[:12]:
            name = item.get("rule") or "?"
            ns = item.get("namespace")
            desc = item.get("description") or ""
            suffix = f" [dim]{ns}[/]" if ns else ""
            branch.add(f"{name}{suffix} {('[dim]- ' + desc[:80] + '[/]') if desc else ''}")

    import_score = (capabilities or {}).get("import_score") or {}
    if import_score:
        branch = tree.add("[bold cyan]import behavior score[/]")
        branch.add(f"score={import_score.get('score', 0)}  hits={len(import_score.get('hits') or {})}")
        clusters = import_score.get("clusters") or {}
        for name, apis in list(clusters.items())[:6]:
            branch.add(f"{name}: [dim]{', '.join(apis[:8])}[/]")
    return Panel(tree, title="[bold magenta]Evidence[/]", border_style="bright_black", box=box.ROUNDED)


def render_packed_banner(packed: dict) -> "Panel":
    """Render packing detection banner."""
    value = (packed or {}).get("packed")
    confidence = (packed or {}).get("confidence")
    evidence = (packed or {}).get("evidence") or []
    title = "Packed binary detection"
    if value is True:
        style = "bold white on red"
        headline = f"LIKELY PACKED / OBFUSCATED  (confidence {confidence:.2f})" if isinstance(confidence, float) else "LIKELY PACKED / OBFUSCATED"
    elif value is False:
        style = "bold green"
        headline = "No strong packing indicators"
    else:
        style = "bold yellow"
        headline = "Packing unknown"
    status = Text(headline, style=style)
    body = "\n".join(f"- {item}" for item in evidence[:5]) if evidence else "No evidence recorded."
    return Panel(Group(status, Text(body, style="white")), title=f"[bold cyan]{title}[/]", border_style="bright_black", box=box.ROUNDED)


def _evidence_overview(scan: dict):
    packed = render_packed_banner(scan.get("packed") or {})
    capabilities = render_capability_summary(scan.get("capabilities") or {})
    if capabilities is None:
        return packed
    grid = Table.grid(expand=True)
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(packed, capabilities)
    return grid


def _metadata_table(scan: dict):
    arch = scan.get("architecture") or {}
    protections = scan.get("protections") or {}
    sections = scan.get("sections") or []

    meta = Table.grid(expand=True)
    meta.add_column(style="dim", width=16)
    meta.add_column(style="white")
    meta.add_row("Format", str(scan.get("format", "unknown")))
    meta.add_row("Architecture", f"{arch.get('arch', '?')}-{arch.get('bits', '?')}")
    meta.add_row("Entry Point", str(arch.get("entry_point", "?")))
    meta.add_row("Analyzer", str(protections.get("source", "static")))

    prot_table = Table(box=box.MINIMAL, expand=True, show_header=True, header_style="bold green")
    prot_table.add_column("Protection")
    prot_table.add_column("State")
    for key in ("nx", "pie", "canary", "relro", "aslr", "cfg", "seh"):
        if key in protections:
            prot_table.add_row(key.upper(), protection_badge(str(protections.get(key))))

    group_items = [meta, prot_table]
    if sections:
        sec_table = Table(title="Sections", box=box.MINIMAL, expand=True, show_header=True, header_style="bold cyan")
        sec_table.add_column("Name")
        sec_table.add_column("Entropy", justify="right")
        sec_table.add_column("Flags")
        sec_table.add_column("Note")
        for section in sections[:8]:
            flags = []
            if section.get("executable"):
                flags.append("X")
            if section.get("writable"):
                flags.append("W")
            sec_table.add_row(
                str(section.get("name", "?")),
                str(section.get("entropy", "?")),
                "".join(flags) or "-",
                str(section.get("note") or ""),
            )
        group_items.append(sec_table)

    return Panel(Group(*group_items), title="[bold cyan]Binary Metadata[/]", border_style="cyan", box=box.ROUNDED)


def _footer(scan: dict, findings: list[dict]):
    high = sum(1 for item in findings if item.get("risk") == "HIGH")
    medium = sum(1 for item in findings if item.get("risk") == "MEDIUM")
    low = sum(1 for item in findings if item.get("risk") == "LOW")
    text = Text()
    text.append("Scan complete", style="bold green")
    text.append("  |  ", style="dim")
    text.append(f"{high} high / {medium} medium / {low} low", style="bold white")
    text.append("  |  ", style="dim")
    text.append("Static analysis only; validate findings with code review and controlled testing.", style="dim")
    return Panel(Align.center(text), border_style="bright_black", box=box.SIMPLE)


def render_report(binary_path: str, scan: dict, findings: list[dict], overall: str, high_count: int, med_count: int, top_fix: str, elapsed: float | None = None) -> str:
    """Render a professional terminal report and return ANSI text."""
    if not RICH_AVAILABLE:
        return _plain_report(binary_path, scan, findings, overall, high_count, med_count, top_fix, elapsed)

    width = _term_width()
    render_console = Console(
        width=width,
        record=True,
        highlight=False,
        force_terminal=True,
        color_system="auto",
        file=StringIO(),
    )
    render_console.print(_render_header(binary_path, scan, overall, elapsed))
    render_console.print()
    render_console.print(_summary_panel(binary_path, scan, findings, overall, high_count, med_count))
    render_console.print()
    render_console.print(_risk_tabs(findings))
    render_console.print()
    render_console.print(_evidence_overview(scan))
    xref_panel = render_xref_tree(scan.get("xrefs") or {})
    if xref_panel is not None:
        render_console.print()
        render_console.print(xref_panel)
    callgraph_panel = render_callgraph_summary(scan.get("callgraph") or {})
    if callgraph_panel is not None:
        render_console.print()
        render_console.print(callgraph_panel)
    render_console.print()
    render_console.print(_next_steps_panel(findings, top_fix))
    additional_panel = _additional_observations_panel(scan)
    if additional_panel is not None:
        render_console.print()
        render_console.print(additional_panel)
    render_console.print()
    render_console.print(_re_tree(scan))
    render_console.print()
    render_console.print(_metadata_table(scan))
    render_console.print()
    render_console.print(_footer(scan, findings))
    return render_console.export_text(styles=True)


def render_welcome(agents: list[tuple[str, str]]) -> None:
    if not RICH_AVAILABLE:
        print("=" * 60)
        print("DEFENSIVE BINARY VULNERABILITY REPORTER")
        print("=" * 60)
        for name, desc in agents:
            print(f"- {name:24} {desc}")
        return

    c = console()
    title = Text("BINARY VULNERABILITY REPORTER", style="bold bright_cyan")
    subtitle = Text("terminal-native static analysis / defensive RE triage", style="dim white")
    c.print(Panel(Align.center(Group(title, subtitle)), border_style="bright_cyan", box=box.DOUBLE, padding=(1, 2)))

    table = Table(title="Active Analysis Agents", box=box.SIMPLE_HEAVY, border_style="bright_black", expand=True)
    table.add_column("Agent", style="bold magenta", no_wrap=True)
    table.add_column("Capability", style="white")
    for name, desc in agents:
        table.add_row(name, desc)
    c.print(table)
    c.print(Panel("Drop an .exe or ELF path, or use: [bold cyan]scan <path>[/], [bold cyan]RE leads[/], [bold cyan]decompile <function>[/].", border_style="green", box=box.ROUNDED))


def render_message(text: str, prefix: str = ">") -> None:
    if not RICH_AVAILABLE:
        print(text)
        return
    c = console()
    value = str(text)
    if "\x1b[" in value:
        c.print(Text.from_ansi(value))
        return
    c.print(Panel(value, title=f"[bold cyan]{prefix}[/]", border_style="bright_black", box=box.ROUNDED))
