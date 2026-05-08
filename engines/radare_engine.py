"""Deterministic radare2 engine (r2pipe).

This engine is responsible for evidence collection only. It never executes the
target binary. It uses radare2 analysis (`aaa`) and JSON commands wherever
possible to extract:

- functions
- imports / exports
- strings
- sections (+ entropy)
- xrefs to strings and imports
- call graph edges

All returned objects are plain dict/list structures suitable for caching.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
import re
from typing import Any


def _safe_hex(value: Any) -> str | Any:
    if isinstance(value, int):
        return hex(value)
    return value


def re_search_suspicious_string(value: str) -> bool:
    return bool(
        re.search(
            r"(?i)flag|password|passwd|secret|token|key|license|serial|admin|correct|wrong|http|cmd\.exe|powershell|/bin/sh|debug|inject|crypto|wallet",
            str(value or ""),
        )
    )


class _SubprocessR2:
    """Small r2-compatible fallback when the r2pipe Python module is absent."""

    def __init__(self, path: str, analysis_cmd: str):
        self.path = path
        self.analysis_cmd = analysis_cmd

    def cmd(self, command: str) -> str:
        if command == self.analysis_cmd:
            return ""
        try:
            result = subprocess.run(
                ["r2", "-q", "-2", "-c", self.analysis_cmd, "-c", command, self.path],
                capture_output=True,
                text=True,
                timeout=45,
            )
        except Exception:
            return ""
        return result.stdout if result.returncode == 0 else ""

    def quit(self) -> None:
        return None


@dataclass(frozen=True)
class RadareConfig:
    """Controls scope/size of radare evidence to keep outputs cache-friendly."""

    max_functions: int = 5000
    max_strings: int = 2000
    max_xref_targets: int = 160
    max_xrefs_per_item: int = 25
    max_callgraph_edges: int = 20000
    analysis_cmd: str = "aaa"


class Radare2Engine:
    def __init__(self, config: RadareConfig | None = None):
        self.config = config or RadareConfig()

    @staticmethod
    def available() -> bool:
        # r2pipe can run with r2 not on PATH in some setups, but we keep this simple.
        return bool(shutil.which("r2"))

    def _open(self, path: str):
        try:
            import r2pipe  # type: ignore
        except Exception as exc:  # pragma: no cover
            if not shutil.which("r2"):
                raise RuntimeError(f"r2pipe not installed and r2 not on PATH: {exc}") from exc
            return _SubprocessR2(path, self.config.analysis_cmd)
        try:
            return r2pipe.open(path, flags=["-2", "-q"])
        except Exception:
            if not shutil.which("r2"):
                raise
            return _SubprocessR2(path, self.config.analysis_cmd)

    def _cmdj(self, r2, command: str):
        out = r2.cmd(command)
        if not out or not str(out).strip():
            return None
        try:
            return json.loads(out)
        except Exception:
            return None

    def _refs_to(self, r2, target: str) -> list[dict]:
        refs = self._cmdj(r2, f"axtj @ {target}") or []
        out = []
        if isinstance(refs, list):
            for ref in refs[: self.config.max_xrefs_per_item]:
                out.append(
                    {
                        "from": _safe_hex(ref.get("from")),
                        "to": _safe_hex(ref.get("to")),
                        "type": ref.get("type"),
                        "function": ref.get("fcn_name") or ref.get("fname"),
                    }
                )
        return out

    def _refs_from(self, r2, target: str) -> list[dict]:
        refs = self._cmdj(r2, f"axfj @ {target}") or []
        out = []
        if isinstance(refs, list):
            for ref in refs[: self.config.max_xrefs_per_item]:
                out.append(
                    {
                        "from": _safe_hex(ref.get("from")),
                        "to": _safe_hex(ref.get("to")),
                        "type": ref.get("type"),
                        "function": ref.get("fcn_name") or ref.get("fname"),
                    }
                )
        return out

    def _extract_call_edges(self, graph, functions: list[dict]) -> list[tuple[str, str]]:
        edges: list[tuple[str, str]] = []
        if isinstance(graph, dict):
            raw_edges = graph.get("edges")
            nodes = graph.get("nodes")
            node_names = {}
            if isinstance(nodes, list):
                for node in nodes:
                    node_id = node.get("id")
                    name = node.get("name") or node.get("title") or node.get("label")
                    if node_id is not None and name:
                        node_names[str(node_id)] = str(name)
            if isinstance(raw_edges, list):
                for e in raw_edges[: self.config.max_callgraph_edges]:
                    src = str(e.get("from") or e.get("source") or "")
                    dst = str(e.get("to") or e.get("target") or "")
                    src = node_names.get(src, src)
                    dst = node_names.get(dst, dst)
                    if src and dst:
                        edges.append((src, dst))
            calls = graph.get("calls")
            if isinstance(calls, dict):
                for src, dsts in calls.items():
                    if not isinstance(dsts, list):
                        continue
                    for dst in dsts:
                        if len(edges) >= self.config.max_callgraph_edges:
                            break
                        if src and dst:
                            edges.append((str(src), str(dst)))

        if not edges:
            by_offset = {item.get("offset"): item.get("name") for item in functions if item.get("offset")}
            for item in functions:
                caller = item.get("name")
                for ref in item.get("_callrefs") or []:
                    if ref.get("type") not in {"CALL", "C", "call", "CODE"}:
                        continue
                    dst = _safe_hex(ref.get("addr") or ref.get("to"))
                    callee = by_offset.get(dst) or str(dst or "")
                    if caller and callee:
                        edges.append((str(caller), callee))

        seen = set()
        unique = []
        for src, dst in edges:
            key = (src, dst)
            if key in seen:
                continue
            seen.add(key)
            unique.append(key)
            if len(unique) >= self.config.max_callgraph_edges:
                break
        return unique

    def analyze(self, path: str) -> dict:
        """Run `aaa` once and collect a structured evidence snapshot."""
        if not self.available():
            return {"error": "radare2 not found on PATH", "source": "radare2"}

        r2 = self._open(path)
        subprocess_fallback = isinstance(r2, _SubprocessR2)
        try:
            r2.cmd(self.config.analysis_cmd)

            info = self._cmdj(r2, "ij") or {}
            bin_info = (info.get("bin") or {}) if isinstance(info, dict) else {}

            entry = bin_info.get("baddr")
            if isinstance(entry, int):
                entry = hex(entry)

            # functions
            funcs = self._cmdj(r2, "aflj") or []
            functions = []
            if isinstance(funcs, list):
                for item in funcs[: self.config.max_functions]:
                    functions.append(
                        {
                            "name": item.get("name") or item.get("realname") or "?",
                            "offset": _safe_hex(item.get("offset")),
                            "size": item.get("size"),
                            "noreturn": bool(item.get("noreturn", False)),
                            "calltype": item.get("calltype"),
                            "_callrefs": item.get("callrefs") or item.get("codexrefs") or [],
                        }
                    )

            # imports / exports
            imports = self._cmdj(r2, "iij") or []
            exports = self._cmdj(r2, "iEj") or []

            imports_clean = []
            if isinstance(imports, list):
                for item in imports:
                    imports_clean.append(
                        {
                            "name": item.get("name") or item.get("plt") or "?",
                            "bind": item.get("bind"),
                            "type": item.get("type"),
                            "plt": _safe_hex(item.get("plt")),
                        }
                    )

            exports_clean = []
            if isinstance(exports, list):
                for item in exports:
                    exports_clean.append(
                        {
                            "name": item.get("name") or "?",
                            "type": item.get("type"),
                            "vaddr": _safe_hex(item.get("vaddr")),
                            "paddr": _safe_hex(item.get("paddr")),
                        }
                    )

            # strings
            strings = self._cmdj(r2, "izzj") or []
            strings_clean = []
            if isinstance(strings, list):
                for s in strings[: self.config.max_strings]:
                    strings_clean.append(
                        {
                            "string": (s.get("string") or "")[:240],
                            "vaddr": _safe_hex(s.get("vaddr")),
                            "paddr": _safe_hex(s.get("paddr")),
                            "size": s.get("size"),
                            "section": s.get("section"),
                            "type": s.get("type"),
                        }
                    )

            # sections + entropy
            sections = self._cmdj(r2, "iSj") or []
            sections_clean = []
            if isinstance(sections, list):
                for sec in sections:
                    perm = sec.get("perm") or ""
                    sections_clean.append(
                        {
                            "name": sec.get("name") or "?",
                            "vaddr": _safe_hex(sec.get("vaddr")),
                            "paddr": _safe_hex(sec.get("paddr")),
                            "size": sec.get("size"),
                            "vsize": sec.get("vsize"),
                            "perm": perm,
                            "executable": "x" in str(perm).lower(),
                            "writable": "w" in str(perm).lower(),
                            "entropy": sec.get("entropy"),
                        }
                    )

            # xrefs collected in the same analyzed r2 session. This keeps
            # conversational evidence fast and avoids re-running aaa per query.
            string_xrefs = []
            string_xref_candidates = [
                s
                for s in strings_clean
                if re_search_suspicious_string(s.get("string") or "")
            ]
            if not string_xref_candidates and not subprocess_fallback:
                string_xref_candidates = strings_clean
            for s in string_xref_candidates[: self.config.max_xref_targets]:
                target = s.get("vaddr") or s.get("paddr")
                text = s.get("string") or ""
                if not target or not text:
                    continue
                refs = self._refs_to(r2, str(target))
                if refs:
                    string_xrefs.append(
                        {
                            "string": text,
                            "string_address": target,
                            "xrefs_to_string": refs,
                        }
                    )

            import_xrefs = []
            for imp in imports_clean[: self.config.max_xref_targets]:
                name = imp.get("name")
                plt = imp.get("plt")
                refs = []
                if plt:
                    refs = self._refs_to(r2, str(plt))
                if not refs and name:
                    refs = self._refs_to(r2, str(name))
                if refs:
                    import_xrefs.append({"import": name, "address": plt, "xrefs_to_import": refs})

            function_xrefs = []
            if not subprocess_fallback:
                for func in functions[: self.config.max_xref_targets]:
                    name = func.get("name")
                    offset = func.get("offset")
                    callers = self._refs_to(r2, str(offset)) if offset else []
                    calls = self._refs_from(r2, str(offset)) if offset else []
                    if callers or calls:
                        function_xrefs.append({"function": name, "address": offset, "called_by": callers, "calls": calls})

            graph = self._cmdj(r2, "agCj")
            edges = self._extract_call_edges(graph, functions)

            for item in functions:
                item.pop("_callrefs", None)

            return {
                "source": "radare2",
                "info": {
                    "arch": bin_info.get("arch"),
                    "bits": bin_info.get("bits"),
                    "os": bin_info.get("os"),
                    "format": bin_info.get("bintype") or bin_info.get("format"),
                    "entry": entry,
                },
                "functions": functions,
                "imports": imports_clean,
                "exports": exports_clean,
                "strings": strings_clean,
                "sections": sections_clean,
                "xrefs": {
                    "strings": string_xrefs[:1000],
                    "imports": import_xrefs[:1000],
                    "functions": function_xrefs[:1000],
                },
                "callgraph_edges": edges,
            }
        finally:
            try:
                r2.quit()
            except Exception:
                pass

    def string_xrefs(self, path: str, string_vaddr_hex: str) -> list[dict]:
        """Return xrefs-to for a string at a given vaddr. `string_vaddr_hex` like '0x401000'."""
        if not self.available():
            return []
        r2 = self._open(path)
        try:
            r2.cmd(self.config.analysis_cmd)
            refs = self._cmdj(r2, f"axtj @ {string_vaddr_hex}") or []
            out = []
            if isinstance(refs, list):
                for ref in refs[: self.config.max_xrefs_per_item]:
                    out.append(
                        {
                            "from": _safe_hex(ref.get("from")),
                            "to": _safe_hex(ref.get("to")),
                            "type": ref.get("type"),
                            "function": ref.get("fcn_name") or ref.get("fname"),
                        }
                    )
            return out
        finally:
            try:
                r2.quit()
            except Exception:
                pass

    def xrefs_to(self, path: str, target: str) -> list[dict]:
        """Xrefs-to any target expression: address, symbol, import. Uses `axtj`."""
        if not self.available():
            return []
        r2 = self._open(path)
        try:
            r2.cmd(self.config.analysis_cmd)
            refs = self._cmdj(r2, f"axtj @ {target}") or []
            out = []
            if isinstance(refs, list):
                for ref in refs[: self.config.max_xrefs_per_item]:
                    out.append(
                        {
                            "from": _safe_hex(ref.get("from")),
                            "to": _safe_hex(ref.get("to")),
                            "type": ref.get("type"),
                            "function": ref.get("fcn_name") or ref.get("fname"),
                        }
                    )
            return out
        finally:
            try:
                r2.quit()
            except Exception:
                pass

    def callgraph_edges(self, path: str) -> list[tuple[str, str]]:
        """Extract call graph edges (caller -> callee) using `agCj` when available."""
        if not self.available():
            return []
        r2 = self._open(path)
        try:
            r2.cmd(self.config.analysis_cmd)
            graph = self._cmdj(r2, "agCj")  # json callgraph
            edges: list[tuple[str, str]] = []
            if isinstance(graph, dict):
                # r2 callgraph json format is not stable; support common shapes.
                # Shape A: {"nodes":[...], "edges":[{"from":"sym.main","to":"sym.foo"}, ...]}
                raw_edges = graph.get("edges")
                if isinstance(raw_edges, list):
                    for e in raw_edges[: self.config.max_callgraph_edges]:
                        src = str(e.get("from") or "")
                        dst = str(e.get("to") or "")
                        if src and dst:
                            edges.append((src, dst))
                # Shape B: {"calls":{"sym.main":["sym.foo", ...], ...}}
                calls = graph.get("calls")
                if isinstance(calls, dict):
                    for src, dsts in calls.items():
                        if not isinstance(dsts, list):
                            continue
                        for dst in dsts:
                            if len(edges) >= self.config.max_callgraph_edges:
                                break
                            if src and dst:
                                edges.append((str(src), str(dst)))
            return edges
        finally:
            try:
                r2.quit()
            except Exception:
                pass
