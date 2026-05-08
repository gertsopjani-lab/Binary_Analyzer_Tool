"""Triage agent builders.

These helpers build Agents SDK `Agent` objects without embedding tool logic.
The deterministic analysis happens in engines/tools; agents only summarize and
prioritize evidence.
"""

from __future__ import annotations

from typing import Callable, Any


def build_analyzer_agent(
    *,
    AgentCls,
    model: str,
    tool_full_pipeline,
    agent_settings: Callable[[int], dict] | None = None,
):
    settings = (agent_settings(900) if agent_settings else {})
    return AgentCls(
        name="AnalyzerAgent",
        model=model,
        tools=[tool_full_pipeline],
        instructions=(
            "Run tool_full_pipeline and render the returned report verbatim. "
            "Then add a short, evidence-backed recap: (1) top hardening action, "
            "(2) top RE starting point (function/import/string) with evidence. "
            "Never invent evidence or speculate without tool output."
        ),
        **settings,
    )


def build_metadata_agent(*, AgentCls, model: str, tool_read_file_metadata, agent_settings=None):
    settings = (agent_settings(450) if agent_settings else {})
    return AgentCls(
        name="MetadataAgent",
        model=model,
        tools=[tool_read_file_metadata],
        instructions=(
            "Use tool_read_file_metadata to return format, architecture, entry point, "
            "file size, and sections/protections. Never execute the binary."
        ),
        **settings,
    )


def build_scanner_agent(*, AgentCls, model: str, tool_checksec, agent_settings=None):
    settings = (agent_settings(450) if agent_settings else {})
    return AgentCls(
        name="ScannerAgent",
        model=model,
        tools=[tool_checksec],
        instructions=(
            "Use tool_checksec to report hardening flags. Explain each missing protection in "
            "plain English and give concrete compiler/linker remediation. Do not speculate."
        ),
        **settings,
    )


def build_symbols_agent(*, AgentCls, model: str, tool_extract_symbols, agent_settings=None):
    settings = (agent_settings(650) if agent_settings else {})
    return AgentCls(
        name="SymbolsAgent",
        model=model,
        tools=[tool_extract_symbols],
        instructions=(
            "Use tool_extract_symbols to list imports/exports and categorize calls into "
            "high-risk vs review-only. Do not claim exploitability without call-site evidence."
        ),
        **settings,
    )


def build_strings_agent(*, AgentCls, model: str, tool_find_strings, agent_settings=None):
    settings = (agent_settings(650) if agent_settings else {})
    return AgentCls(
        name="StringsAgent",
        model=model,
        tools=[tool_find_strings],
        instructions=(
            "Use tool_find_strings to surface high-signal strings (license, secrets, URLs, debug). "
            "Explain why the strings matter and what evidence supports that."
        ),
        **settings,
    )


def build_secrets_agent(*, AgentCls, model: str, tool_scan_secrets, agent_settings=None):
    settings = (agent_settings(650) if agent_settings else {})
    return AgentCls(
        name="SecretsAgent",
        model=model,
        tools=[tool_scan_secrets],
        instructions=(
            "Use tool_scan_secrets to find embedded secrets (keys, tokens, credentials). "
            "Explain why client-side secrets are extractable and give concrete remediation."
        ),
        **settings,
    )


def build_pe_scanner_agent(*, AgentCls, model: str, tool_pe_scan, agent_settings=None):
    settings = (agent_settings(450) if agent_settings else {})
    return AgentCls(
        name="PEScannerAgent",
        model=model,
        tools=[tool_pe_scan],
        instructions=(
            "Use tool_pe_scan to report DEP/ASLR/CFG/SEH/SecurityCookie plus imports and entropy. "
            "Cite concrete evidence from this binary."
        ),
        **settings,
    )

